/*
 * Copyright (C) 2003 Andras Varga; CTIE, Monash University, Australia
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "inet/common/Simsignals.h"
#include "inet/linklayer/ethernet/EtherHub.h"

namespace inet {

Define_Module(EtherHub);

inline std::ostream& operator<<(std::ostream& os, cMessage *msg)
{
    os << "(" << msg->getClassName() << ")" << msg->getFullName();
    return os;
}

inline std::ostream& operator<<(std::ostream& os, const EtherHub::GateInfo& tr)
{
    os << "outId:" << tr.outgoingOrigId << ", numInIds:" << tr.forwardFromPorts.size() << ", collision:" << tr.outgoingCollision << ", start:" << tr.outgoingStartTime;
    return os;
}

EtherHub::~EtherHub()
{
    for (auto& gateInfo: gateInfos) {
        delete gateInfo.incomingSignal;
    }
}

void EtherHub::initialize()
{
    numPorts = gateSize("ethg");
    inputGateBaseId = gateBaseId("ethg$i");
    outputGateBaseId = gateBaseId("ethg$o");
    gateInfos.resize(numPorts);

    setTxUpdateSupport(true);

    numMessages = 0;
    WATCH(numMessages);
    WATCH_VECTOR(gateInfos);

    // ensure we receive frames when their first bits arrive
    for (int i = 0; i < numPorts; i++)
        gate(inputGateBaseId + i)->setDeliverImmediately(true);
    subscribe(PRE_MODEL_CHANGE, this);    // for cPrePathCutNotification signal
    subscribe(POST_MODEL_CHANGE, this);    // we'll need to do the same for dynamically added gates as well

    checkConnections(true);
}

void EtherHub::checkConnections(bool errorWhenAsymmetric)
{
    int numActivePorts = 0;
    datarate = 0.0;
    dataratesDiffer = false;

    for (int i = 0; i < numPorts; i++) {
        cGate *igate = gate(inputGateBaseId + i);
        cGate *ogate = gate(outputGateBaseId + i);
        if (!igate->isConnected() && !ogate->isConnected())
            continue;

        if (!igate->isConnected() || !ogate->isConnected()) {
            // half connected gate
            if (errorWhenAsymmetric)
                throw cRuntimeError("The input or output gate not connected at port %i", i);
            dataratesDiffer = true;
            EV << "The input or output gate not connected at port " << i << ".\n";
            continue;
        }

        numActivePorts++;
        double drate = igate->getIncomingTransmissionChannel()->getNominalDatarate();

        if (numActivePorts == 1)
            datarate = drate;
        else if (datarate != drate) {
            if (errorWhenAsymmetric)
                throw cRuntimeError("The input datarate at port %i differs from datarates of previous ports", i);
            dataratesDiffer = true;
            EV << "The input datarate at port " << i << " differs from datarates of previous ports.\n";
        }

        cChannel *outTrChannel = ogate->getTransmissionChannel();
        drate = outTrChannel->getNominalDatarate();

        if (datarate != drate) {
            if (errorWhenAsymmetric)
                throw cRuntimeError("The output datarate at port %i differs from datarates of previous ports", i);
            dataratesDiffer = true;
            EV << "The output datarate at port " << i << " differs from datarates of previous ports.\n";
        }

        if (!outTrChannel->isSubscribed(POST_MODEL_CHANGE, this))
            outTrChannel->subscribe(POST_MODEL_CHANGE, this);
    }
}

void EtherHub::receiveSignal(cComponent *source, simsignal_t signalID, cObject *obj, cObject *details)
{
    Enter_Method_Silent();

    if (signalID == POST_MODEL_CHANGE) {
    }
    else if (signalID == POST_MODEL_CHANGE) {
        // if new gates have been added, we need to call setDeliverImmediately(true) on them
        if (cPostGateVectorResizeNotification *notif = dynamic_cast<cPostGateVectorResizeNotification *>(obj)) {
            if (strcmp(notif->gateName, "ethg") == 0) {
                int newSize = gateSize("ethg");
                for (int i = notif->oldSize; i < newSize; i++)
                    gate(inputGateBaseId + i)->setDeliverImmediately(true);
                gateInfos.resize(newSize);
            }
            return;
        }
        else if (cPostPathCreateNotification *connNotif = dynamic_cast<cPostPathCreateNotification *>(obj)) {
            if ((this == connNotif->pathStartGate->getOwnerModule()) || (this == connNotif->pathEndGate->getOwnerModule()))
                checkConnections(false);
            return;
        }
        else if (cPostPathCutNotification *cutNotif = dynamic_cast<cPostPathCutNotification *>(obj)) {
            if ((this == cutNotif->pathStartGate->getOwnerModule()) || (this == cutNotif->pathEndGate->getOwnerModule()))
                checkConnections(false);
            return;
        }
        else if (cPostParameterChangeNotification *parNotif = dynamic_cast<cPostParameterChangeNotification *>(obj)) {
            cChannel *channel = dynamic_cast<cDatarateChannel *>(parNotif->par->getOwner());
            if (channel) {
                cGate *gate = channel->getSourceGate();
                if (gate->pathContains(this))
                    checkConnections(false);
            }
            return;
        }
    }
}

void EtherHub::handleMessage(cMessage *msg)
{
    if (dataratesDiffer)
        checkConnections(true);

    EthernetSignalBase *signal = check_and_cast<EthernetSignalBase *>(msg);
    if (signal->getSrcMacFullDuplex() != false)
        throw cRuntimeError("Ethernet misconfiguration: MACs on the Ethernet HUB must be all in half-duplex mode, check it in module '%s'", signal->getSenderModule()->getFullPath().c_str());

    // Handle frame sent down from the network entity: send out on every other port
    int arrivalPort = msg->getArrivalGate()->getIndex();
    EV << "Frame " << msg << " arrived on port " << arrivalPort << ", broadcasting on all other ports\n";

    numMessages++;
    emit(packetReceivedSignal, msg);

    if (numPorts <= 1) {
        delete msg;
        return;
    }

    simtime_t now = simTime();
    long incomingOrigId = signal->isUpdate() ? signal->getOrigPacketId() : signal->getId();

    if (signal->isUpdate()) {
        ASSERT(gateInfos[arrivalPort].incomingOrigId == incomingOrigId);
        ASSERT(gateInfos[arrivalPort].incomingSignal != nullptr);
        delete gateInfos[arrivalPort].incomingSignal;
    }
    else {
        ASSERT(gateInfos[arrivalPort].incomingOrigId == -1);
        gateInfos[arrivalPort].incomingOrigId = incomingOrigId;
        ASSERT(gateInfos[arrivalPort].incomingSignal == nullptr);
    }

    gateInfos[arrivalPort].incomingSignal = signal;

    for (int outPort = 0; outPort < numPorts; outPort++) {
        if (outPort != arrivalPort) {
            cGate *ogate = gate(outputGateBaseId + outPort);
            if (!ogate->isConnected())
                continue;

            if (gateInfos[outPort].forwardFromPorts.empty()) {
                // new correct transmisssion started
                EthernetSignalBase *signalCopy = signal->dup();
                ASSERT(!ogate->getTransmissionChannel()->isBusy());
                ASSERT(signal->isReceptionStart());
                gateInfos[outPort].forwardFromPorts.insert(arrivalPort);
                gateInfos[outPort].outgoingOrigId = signalCopy->getId();
                gateInfos[outPort].outgoingStartTime = now;
                gateInfos[outPort].outgoingCollision = false;
                send(signalCopy, SendOptions().duration(signal->getDuration()), ogate);
            }
            else {
                gateInfos[outPort].forwardFromPorts.insert(arrivalPort);
                ASSERT(now + signal->getRemainingDuration() - signal->getDuration() >= gateInfos[outPort].outgoingStartTime);
                if (!gateInfos[outPort].outgoingCollision && gateInfos[outPort].forwardFromPorts.size() == 1) {
                    // current single transmisssion updated
                    ASSERT(signal->isReceptionEnd() || ogate->getTransmissionChannel()->isBusy());
                    EthernetSignalBase *signalCopy = signal->dup();
                    send(signalCopy, SendOptions().updateTx(gateInfos[outPort].outgoingOrigId).duration(signal->getDuration()), ogate);
                }
                else {
                    // collision
                    gateInfos[outPort].outgoingCollision = true;
                    simtime_t newEnd = now;
                    for (auto inPort: gateInfos[outPort].forwardFromPorts) {
                        simtime_t curEnd = gateInfos[inPort].incomingSignal->getArrivalTime() + gateInfos[inPort].incomingSignal->getRemainingDuration();
                        if (curEnd > newEnd)
                            newEnd = curEnd;
                    }
                    EthernetSignalBase *signalCopy = new EthernetSignalBase("collision");
                    simtime_t duration = newEnd - gateInfos[outPort].outgoingStartTime;
                    signalCopy->setBitLength(duration.dbl() * datarate);
                    signalCopy->setBitrate(datarate);
                    signalCopy->setBitError(true);
                    send(signalCopy, SendOptions().updateTx(gateInfos[outPort].outgoingOrigId).duration(duration), ogate);
                }
            }
            if (signal->isReceptionEnd()) {
                gateInfos[outPort].forwardFromPorts.erase(arrivalPort);
                if (gateInfos[outPort].forwardFromPorts.empty()) {
                    // transmisssion finished
                    gateInfos[outPort].outgoingOrigId = -1;
                    gateInfos[outPort].outgoingStartTime = now;
                    gateInfos[outPort].outgoingCollision = false;
                }
            }
        }
    }
    if (signal->isReceptionEnd()) {
        gateInfos[arrivalPort].incomingOrigId = -1;
        delete gateInfos[arrivalPort].incomingSignal;
        gateInfos[arrivalPort].incomingSignal = nullptr;
    }
}

void EtherHub::finish()
{
    simtime_t t = simTime();
    recordScalar("simulated time", t);

    if (t > 0)
        recordScalar("messages/sec", numMessages / t);
}

} // namespace inet

