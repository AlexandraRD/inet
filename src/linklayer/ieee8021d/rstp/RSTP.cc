//
// Copyright (C) 2011 Juan Luis Garrote Molinero
// Copyright (C) 2013 Zsolt Prontvai
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#include "RSTP.h"

#include "InterfaceEntry.h"
#include "ModuleAccess.h"
#include "NodeOperations.h"
#include "NodeStatus.h"

Define_Module(RSTP);

RSTP::RSTP()
{
    macTable = NULL;
    helloM = new cMessage("itshellotime", SELF_HELLOTIME);
    forwardM = new cMessage("upgrade", SELF_UPGRADE);
    migrateM = new cMessage("timetodesignate", SELF_TIMETODESIGNATE);
}

RSTP::~RSTP()
{
    cancelAndDelete(helloM);
    cancelAndDelete(forwardM);
    cancelAndDelete(migrateM);
}

void RSTP::initialize(int stage)
{
    if (stage == 0)
    {
        autoEdge = par("autoEdge");
        maxAge = par("maxAge");
        treeColoring = par("treeColoring");
        priority = par("priority");
        tcWhileTime = par("tcWhileTime");
        hellotime = par("helloTime");
        fwdDelay = par("fwdDelay");
        migrateTime = par("migrateTime");

        macTable = check_and_cast<MACAddressTable *>(getParentModule()->getSubmodule(par("macTableName")));
        ifTable = check_and_cast<IInterfaceTable*>(this->getParentModule()->getSubmodule(par("interfaceTableName")));
        portCount = this->getParentModule()->gate("ethg$o", 0)->getVectorSize();
    }

    if (stage == 1) // "auto" MAC addresses assignment takes place in stage 0
    {
        NodeStatus *nodeStatus = dynamic_cast<NodeStatus *>(findContainingNode(this)->getSubmodule("status"));
        isOperational = (!nodeStatus) || nodeStatus->getState() == NodeStatus::UP;

        // gets the bridge's mac address
        InterfaceEntry * ifEntry = ifTable->getInterface(0);
        if (ifEntry != NULL)
        {
            address = ifEntry->getMacAddress();
        }
        else
        {
            EV_INFO<<"interface not found. Is not this module connected to another BEB?"<<endl;
            EV_INFO<<"Setting AAAAAA000001 as backbone mac address."<<endl;
            address.setAddress("AAAAAA000001");
        }

        initPorts();

        // programming next auto-messages.
        scheduleAt(simTime(), helloM);
        scheduleAt(simTime() + fwdDelay, forwardM);
        scheduleAt(simTime() + migrateTime, migrateM);
    }

    if (stage == 1)
    {
        printState();
        colorRootPorts();
    }
}

void RSTP::handleMessage(cMessage *msg)
{
    // it can receive BPDU or self messages
    if (!isOperational)
    {
        EV<< "Message '" << msg << "' arrived when module status is down, dropped\n";
        delete msg;
        return;
    }

    if(msg->isSelfMessage())
    {
        switch (msg->getKind())
        {
            case SELF_HELLOTIME:
            handleHelloTime(msg);
            break;

            case SELF_UPGRADE:
            // designated ports state upgrading (discarding-->learning, learning-->forwarding)
            handleUpgrade(msg);
            break;

            case SELF_TIMETODESIGNATE:
            // not assigned ports switch to designated.
            handleMigrate(msg);
            break;

            default:
            error("Unknown self message");
            break;
        }
    }
    else
    {
        EV_INFO<<"BPDU received at RSTP module."<<endl;
        handleIncomingFrame(check_and_cast<BPDU *> (msg)); // handling BPDU

    }

    EV_DETAIL<<"Post message State"<<endl;
    printState();
}

void RSTP::handleMigrate(cMessage * msg)
{
    for (unsigned int i = 0; i < portCount; i++)
    {
        Ieee8021DInterfaceData * iPort = getPortInterfaceData(i);
        if (iPort->getRole() == Ieee8021DInterfaceData::NOTASSIGNED)
        {
            iPort->setRole(Ieee8021DInterfaceData::DESIGNATED);
            iPort->setState(Ieee8021DInterfaceData::DISCARDING); // contest to become forwarding.
        }
    }
    scheduleAt(simTime() + migrateTime, msg); // programming next switch to designate
}

void RSTP::handleUpgrade(cMessage * msg)
{
    for (unsigned int i = 0; i < portCount; i++)
    {
        Ieee8021DInterfaceData * iPort = getPortInterfaceData(i);
        if (iPort->getRole() == Ieee8021DInterfaceData::DESIGNATED)
        {
            if (iPort->getState() == Ieee8021DInterfaceData::DISCARDING)
                iPort->setState(Ieee8021DInterfaceData::LEARNING);
            if (iPort->getState() == Ieee8021DInterfaceData::LEARNING)
            {
                iPort->setState(Ieee8021DInterfaceData::FORWARDING);
                //flushing other ports
                //TCN over all active ports
                for (unsigned int j = 0; j < portCount; j++)
                {
                    Ieee8021DInterfaceData * jPort = getPortInterfaceData(j);
                    jPort->setTCWhile(simulation.getSimTime()+tcWhileTime);
                    if (j != i)
                        macTable->flush(j);
                }
            }
        }
    }
    scheduleAt(simTime() + fwdDelay, msg); // programming next upgrade
}

void RSTP::handleHelloTime(cMessage * msg)
{
    EV_DETAIL<<"Hello time."<<endl;
    printState();
    for(unsigned int i=0;i<portCount;i++)
    {
        // sends hello through all active (learning, forwarding or not assigned) ports
        // increments LostBPDU just from ROOT, ALTERNATE and BACKUP
        Ieee8021DInterfaceData * iPort = getPortInterfaceData(i);
        if(!iPort->isEdge()
                && (iPort->getRole() == Ieee8021DInterfaceData::ROOT
                        || iPort->getRole() == Ieee8021DInterfaceData::ALTERNATE
                        || iPort->getRole() == Ieee8021DInterfaceData::BACKUP))
        {
            iPort->setLostBPDU(iPort->getLostBPDU()+1);
            if(iPort->getLostBPDU()>3) // 3 HelloTime without the best BPDU.
            {
                // starts contest
                if(iPort->getRole() == Ieee8021DInterfaceData::ROOT)
                {
                    // looking for the best ALTERNATE port
                    int candidato=getBestAlternate();
                    if(candidato!=-1)
                    {
                        // if an alternate gate has been found, switch to alternate
                        EV_DETAIL<<"To Alternate"<<endl;
                        // ALTERNATE->ROOT. DISCARDING->FORWARDING (immediately)
                        // old root gate goes to DESIGNATED and DISCARDING
                        // a new contest should be done to determine the new root path from this LAN
                        // updating root vector.
                        Ieee8021DInterfaceData * candidatoPort = getPortInterfaceData(candidato);
                        iPort->setRole(Ieee8021DInterfaceData::DESIGNATED);
                        iPort->setState(Ieee8021DInterfaceData::DISCARDING);// if there is not a better BPDU, that will become FORWARDING
                        initInterfacedata(i);// reset, then a new BPDU will be allowed to upgrade the best received info for this port
                        candidatoPort->setRole(Ieee8021DInterfaceData::ROOT);
                        candidatoPort->setState(Ieee8021DInterfaceData::FORWARDING);
                        candidatoPort->setLostBPDU(0);
                        // flushing other ports
                        // sending TCN over all active ports
                        for(unsigned int j=0;j<portCount;j++)
                        {
                            Ieee8021DInterfaceData * jPort = getPortInterfaceData(j);
                            jPort->setTCWhile(simulation.getSimTime()+tcWhileTime);
                            if(j!=(unsigned int)candidato)
                            macTable->flush(j);
                        }
                        macTable->copyTable(i,candidato); // copy cache from old to new root
                    }
                    else
                    {
                        // alternate not found, selects a new root
                        EV_DETAIL<<"Alternate not found. Starts from beginning."<<endl;
                        // initializing ports, start from the beginning
                        initPorts();
                    }
                }
                else if(iPort->getRole() == Ieee8021DInterfaceData::ALTERNATE
                        ||iPort->getRole() == Ieee8021DInterfaceData::BACKUP)
                {
                    // it should take care of this LAN, switching to designated
                    iPort->setRole(Ieee8021DInterfaceData::DESIGNATED);
                    iPort->setState(Ieee8021DInterfaceData::DISCARDING);// a new content will start in case of another switch were in alternate
                    // if there is no problem, this will become forwarding in a few seconds
                    initInterfacedata(i);
                }
                iPort->setLostBPDU(0); // reseting lost bpdu counter after a change.
            }
        }
    }
    sendBPDUs(); // generating and sending new BPDUs
    sendTCNtoRoot();
    colorRootPorts();
    scheduleAt(simTime()+hellotime, msg);// programming next hello time
}

void RSTP::checkTC(BPDU * frame, int arrival)
{
    Ieee8021DInterfaceData * port = getPortInterfaceData(arrival);
    if ((frame->getTcFlag() == true) && (port->getState() == Ieee8021DInterfaceData::FORWARDING))
    {
        this->getParentModule()->bubble("TCN received");
        for (unsigned int i = 0; i < portCount; i++)
        {
            if ((int) i != arrival)
            {
                Ieee8021DInterfaceData * port2 = getPortInterfaceData(i);
                // flushing other ports
                // TCN over other ports
                macTable->flush(i);
                port2->setTCWhile(simulation.getSimTime()+tcWhileTime);
            }
        }
    }
}

void RSTP::handleBK(BPDU * frame, unsigned int arrival)
{
    Ieee8021DInterfaceData * port = getPortInterfaceData(arrival);
    if ((frame->getPortPriority() < port->getPortPriority())
            || ((frame->getPortPriority() == port->getPortPriority()) && (frame->getPortNum() < arrival)))
    {
        // flushing arrival port
        macTable->flush(arrival);
        port->setRole(Ieee8021DInterfaceData::BACKUP);
        port->setState(Ieee8021DInterfaceData::DISCARDING);
        port->setLostBPDU(0);
    }
    else if (frame->getPortPriority() > port->getPortPriority()
            || (frame->getPortPriority() == port->getPortPriority() && frame->getPortNum() > arrival))
    {
        Ieee8021DInterfaceData * port2 = getPortInterfaceData(frame->getPortNum());
        // flushing sender port
        macTable->flush(frame->getPortNum()); // portNum is sender port number, it is not arrival port
        port2->setRole(Ieee8021DInterfaceData::BACKUP);
        port2->setState(Ieee8021DInterfaceData::DISCARDING);
        port2->setLostBPDU(0);
    }
    else
    {
        Ieee8021DInterfaceData * port2 = getPortInterfaceData(frame->getPortNum());
        // unavoidable loop, received its own message at the same port
        // switch to disabled
        EV_DETAIL<<"Unavoidable loop. Received its own message at the same port. To disabled."<<endl;
        // flushing that port
        macTable->flush(frame->getPortNum()); // portNum is sender port number, it is not arrival port
        port2->setRole(Ieee8021DInterfaceData::DISABLED);
        port2->setState(Ieee8021DInterfaceData::DISCARDING);
    }
}

void RSTP::handleIncomingFrame(BPDU *frame)
{
    // incoming BPDU handling
    printState();

    // checking message age
    Ieee802Ctrl * etherctrl = check_and_cast<Ieee802Ctrl *>(frame->removeControlInfo());
    int arrival = etherctrl->getInterfaceId();
    MACAddress src = etherctrl->getSrc();
    delete etherctrl;
    if (frame->getMessageAge() < maxAge)
    {
        // checking TC
        checkTC(frame, arrival); // sets TCWhile if arrival port was FORWARDING

        int r = getRootIndex();

        // checking possible backup
        if (src.compareTo(address) == 0)// more than one port in the same LAN
            handleBK(frame, arrival);
        else
        {
            //three challenges.
            //
            //first:  vs best received BPDU for that port --------->caso
            //second: vs root BPDU--------------------------------->caso1
            //third:  vs BPDU that would be sent from this Bridge.->caso2
            Ieee8021DInterfaceData * arrivalPort = getPortInterfaceData(arrival);
            int caso = 0;
            bool Flood = false;
            caso = compareInterfacedata(arrival, frame, arrivalPort->getLinkCost());
            EV_DEBUG<<"caso: "<<caso<<endl;
            if ((caso > 0) && (frame->getRootAddress().compareTo(address) != 0)) // root will not participate in a loop with its own address
            {
                // update that port rstp info
                updateInterfacedata(frame, arrival);
                if (r == -1)
                {
                    // there was no root
                    arrivalPort->setRole(Ieee8021DInterfaceData::ROOT);
                    arrivalPort->setState(Ieee8021DInterfaceData::FORWARDING);
                    arrivalPort->setLostBPDU(0);
                    // flushing other ports
                    // TCN over all ports
                    for (unsigned int j = 0; j < portCount; j++)
                    {
                        Ieee8021DInterfaceData * jPort = getPortInterfaceData(j);
                        jPort->setTCWhile(simulation.getSimTime()+tcWhileTime);
                        if (j != (unsigned int) arrival)
                            macTable->flush(j);
                    }
                    Flood = true;
                }
                else
                {
                    Ieee8021DInterfaceData * rootPort = getPortInterfaceData(r);
                    // there was a Root -> challenge 2 (compare with the root)
                    int caso2 = compareInterfacedata(r, frame, arrivalPort->getLinkCost()); // comparing with root port's BPDU
                    EV_DEBUG<<"caso2: "<<caso2<<endl;
                    int caso3 = 0;

                    switch (caso2)
                    {
                        case 0:// double link to the same port of the root source -> Tie breaking (better local port first)
                            if (rootPort->getPortPriority() < arrivalPort->getPortPriority()
                                    || (rootPort->getPortPriority() == arrivalPort->getPortPriority() && r < arrival))
                            {
                                // flushing that port
                                macTable->flush(arrival);
                                arrivalPort->setRole(Ieee8021DInterfaceData::ALTERNATE);
                                arrivalPort->setState(Ieee8021DInterfaceData::DISCARDING);
                                arrivalPort->setLostBPDU(0);
                            }
                            else
                            {
                                if (arrivalPort->getState() != Ieee8021DInterfaceData::FORWARDING)
                                {
                                    // flushing other ports
                                    // TCN over all ports
                                    for (unsigned int j = 0; j < portCount; j++)
                                    {
                                        Ieee8021DInterfaceData * jPort = getPortInterfaceData(j);
                                        jPort->setTCWhile(simulation.getSimTime()+tcWhileTime);
                                        if (j != (unsigned int) arrival)
                                            macTable->flush(j);
                                    }
                                }
                                else
                                    macTable->flush(r); // flushing r, needed in case arrival were previously FORWARDING
                                rootPort->setRole(Ieee8021DInterfaceData::ALTERNATE);
                                rootPort->setState(Ieee8021DInterfaceData::DISCARDING); // comes from root, preserve lostBPDU
                                arrivalPort->setRole(Ieee8021DInterfaceData::ROOT);
                                arrivalPort->setState(Ieee8021DInterfaceData::FORWARDING);
                                arrivalPort->setLostBPDU(0);
                                macTable->copyTable(r, arrival); // copy cache from old to new root
                                // the change does not deserve flooding
                            }
                            break;

                        case 1: // new port rstp info is better than the root in another gate -> root change
                            for (unsigned int i = 0; i < portCount; i++)
                            {
                                Ieee8021DInterfaceData * iPort = getPortInterfaceData(i);
                                if (!iPort->isEdge())   // avoiding clients reseting
                                {
                                    if (arrivalPort->getState() != Ieee8021DInterfaceData::FORWARDING)
                                        iPort->setTCWhile(simulation.getSimTime()+tcWhileTime);
                                        macTable->flush(i);
                                        if(i!=(unsigned)arrival)
                                        {
                                            iPort->setRole(Ieee8021DInterfaceData::NOTASSIGNED);
                                            iPort->setState(Ieee8021DInterfaceData::DISCARDING);
                                            initInterfacedata(i);
                                        }
                                    }
                                }
                                arrivalPort->setRole(Ieee8021DInterfaceData::ROOT);
                                arrivalPort->setState(Ieee8021DInterfaceData::FORWARDING);
                                arrivalPort->setLostBPDU(0);

                                Flood=true;
                                break;

                                case 2:// same that Root but better RPC
                                case 3:// same that Root RPC but better source
                                case 4:// same that root RPC and source but better port

                                if(arrivalPort->getState()!=Ieee8021DInterfaceData::FORWARDING)
                                {
                                    // flushing other ports
                                    // TCN over all ports
                                    for(unsigned int j=0;j<portCount;j++)
                                    {
                                        Ieee8021DInterfaceData * jPort = getPortInterfaceData(j);
                                        jPort->setTCWhile(simulation.getSimTime()+tcWhileTime);
                                        if(j!=(unsigned int)arrival)
                                        macTable->flush(j);
                                    }
                                }
                                arrivalPort->setRole(Ieee8021DInterfaceData::ROOT);
                                arrivalPort->setState(Ieee8021DInterfaceData::FORWARDING);
                                arrivalPort->setLostBPDU(0);
                                rootPort->setRole(Ieee8021DInterfaceData::ALTERNATE); // temporary, just one port can be root at contest time
                                macTable->copyTable(r,arrival);// copy cache from old to new root
                                Flood=true;
                                caso3=contestInterfacedata(r);
                                EV_DEBUG<<"caso3: "<<caso3<<endl;
                                if(caso3>=0)
                                {
                                    rootPort->setRole(Ieee8021DInterfaceData::ALTERNATE);
                                    // not lostBPDU reset
                                    // flushing r
                                    macTable->flush(r);
                                }
                                else
                                rootPort->setRole(Ieee8021DInterfaceData::DESIGNATED);
                                rootPort->setState(Ieee8021DInterfaceData::DISCARDING);
                                break;

                                case -1: // worse root
                                sendBPDU(arrival);// BPDU to show him a better root as soon as possible
                                break;

                                case -2:// same Root but worse RPC
                                case -3:// same Root RPC but worse source
                                case -4:// same Root RPC and source but worse port
                                caso3=contestInterfacedata(frame,arrival);// case 0 not possible
                                EV_DEBUG<<"caso3: "<<caso3<<endl;
                                if(caso3<0)
                                {
                                    arrivalPort->setRole(Ieee8021DInterfaceData::DESIGNATED);
                                    arrivalPort->setState(Ieee8021DInterfaceData::DISCARDING);
                                    sendBPDU(arrival); // BPDU to show him a better root as soon as possible
                                }
                                else
                                {
                                    // flush arrival
                                    macTable->flush(arrival);
                                    arrivalPort->setRole(Ieee8021DInterfaceData::ALTERNATE);
                                    arrivalPort->setState(Ieee8021DInterfaceData::DISCARDING);
                                    arrivalPort->setLostBPDU(0);
                                }
                                break;
                            }
                            if (rootPort->getRole() == Ieee8021DInterfaceData::ROOT)
                                colorLink(r, "#a5ffff", 3);
                            else
                                colorLink(r, "#000000", 1);
                        }
                    }
                    else if((src.compareTo(arrivalPort->getBridgeAddress())==0) // worse or similar, but the same source
                            &&(frame->getRootAddress().compareTo(address)!=0))// root will not participate
                    {
                        // source has updated BPDU information
                        switch(caso)
                        {
                            case 0:
                            arrivalPort->setLostBPDU(0);  // same BPDU, not updated
                            break;

                            case -1:// worse root
                            if(arrivalPort->getRole() == Ieee8021DInterfaceData::ROOT)
                            {
                                int alternative=getBestAlternate(); // searching old alternate
                                if(alternative>=0)
                                {
                                    Ieee8021DInterfaceData * alternativePort = getPortInterfaceData(alternative);
                                    arrivalPort->setRole(Ieee8021DInterfaceData::DESIGNATED);
                                    arrivalPort->setState(Ieee8021DInterfaceData::DISCARDING);
                                    macTable->copyTable(arrival,alternative); // copy cache from old to new root
                                    // flushing other ports
                                    // TCN over all ports, alternative was alternate
                                    for(unsigned int j=0;j<portCount;j++)
                                    {
                                        Ieee8021DInterfaceData * jPort = getPortInterfaceData(j);
                                        jPort->setTCWhile(simulation.getSimTime()+tcWhileTime);
                                        if(j!=(unsigned int)alternative)
                                        macTable->flush(j);
                                    }
                                    alternativePort->setRole(Ieee8021DInterfaceData::ROOT);
                                    alternativePort->setState(Ieee8021DInterfaceData::FORWARDING); // comes from alternate, preserves lostBPDU
                                    updateInterfacedata(frame,arrival);
                                    sendBPDU(arrival);// show him a better Root as soon as possible
                                }
                                else
                                {
                                    int caso2=0;
                                    initPorts();// allowing other ports to contest again
                                    // flushing all ports
                                    for(unsigned int j=0;j<portCount;j++)
                                    macTable->flush(j);
                                    caso2=compareInterfacedata(arrival,frame,arrivalPort->getLinkCost());
                                    EV_DEBUG<<"caso2: "<<caso2<<endl;
                                    if(caso2>0)
                                    {
                                        updateInterfacedata(frame,arrival); // if this module is not better, keep it as a ROOT
                                        arrivalPort->setRole(Ieee8021DInterfaceData::ROOT);
                                        arrivalPort->setState(Ieee8021DInterfaceData::FORWARDING);
                                    }
                                    // propagating new information
                                    Flood=true;
                                }
                            }
                            else if(arrivalPort->getRole() == Ieee8021DInterfaceData::ALTERNATE)
                            {
                                arrivalPort->setRole(Ieee8021DInterfaceData::DESIGNATED);
                                arrivalPort->setState(Ieee8021DInterfaceData::DISCARDING);
                                updateInterfacedata(frame,arrival);
                                sendBPDU(arrival); //Show him a better Root as soon as possible
                            }
                            break;

                            case -2:
                            case -3:
                            case -4:
                            if(arrivalPort->getRole() == Ieee8021DInterfaceData::ROOT)
                            {
                                arrivalPort->setLostBPDU(0);
                                int alternative=getBestAlternate(); // searching old alternate
                                if(alternative>=0)
                                {
                                    Ieee8021DInterfaceData * alternativePort = getPortInterfaceData(alternative);
                                    int caso2=0;
                                    caso2=compareInterfacedata(alternative,frame,arrivalPort->getLinkCost());
                                    EV_DEBUG<<"caso2: "<<caso2<<endl;
                                    if(caso2<0) // if alternate is better, change
                                    {
                                        alternativePort->setRole(Ieee8021DInterfaceData::ROOT);
                                        alternativePort->setState(Ieee8021DInterfaceData::FORWARDING);
                                        arrivalPort->setRole(Ieee8021DInterfaceData::DESIGNATED); // temporary, just one port can be root at contest time
                                        int caso3=0;
                                        caso3=contestInterfacedata(frame,arrival);
                                        EV_DEBUG<<"caso3: "<<caso3<<endl;
                                        if(caso3<0)
                                        arrivalPort->setRole(Ieee8021DInterfaceData::DESIGNATED);
                                        else
                                        arrivalPort->setRole(Ieee8021DInterfaceData::ALTERNATE);
                                        arrivalPort->setState(Ieee8021DInterfaceData::DISCARDING);
                                        // flushing other ports
                                        // TC over all ports
                                        for(unsigned int j=0;j<portCount;j++)
                                        {
                                            Ieee8021DInterfaceData * jPort = getPortInterfaceData(j);
                                            jPort->setTCWhile(simulation.getSimTime()+tcWhileTime);
                                            if(j!=(unsigned int)alternative)
                                            macTable->flush(j);
                                        }
                                        macTable->copyTable(arrival,alternative); // copy cache from old to new root
                                    }
                                }
                                updateInterfacedata(frame,arrival);
                                // propagating new information
                                Flood=true;
                                // if alternate is worse than root, or there is not alternate, keep old root as root
                            }
                            else if(arrivalPort->getRole() == Ieee8021DInterfaceData::ALTERNATE)
                            {
                                int caso2=0;
                                caso2=contestInterfacedata(frame,arrival);
                                EV_DEBUG<<"caso2: "<<caso2<<endl;
                                if(caso2<0)
                                {
                                    arrivalPort->setRole(Ieee8021DInterfaceData::DESIGNATED); // if the frame is worse than this module generated frame, switch to Designated/Discarding
                                    arrivalPort->setState(Ieee8021DInterfaceData::DISCARDING);
                                    sendBPDU(arrival);// show him a better BPDU as soon as possible
                                }
                                else
                                {
                                    arrivalPort->setLostBPDU(0); // if it is better than this module generated frame, keep it as alternate
                                    // this does not deserve expedited BPDU
                                }
                            }
                            updateInterfacedata(frame,arrival);
                            break;
                        }
                    }
            if (Flood)
            {
                sendBPDUs(); //expedited BPDU
                sendTCNtoRoot();
            }
        }
    }
    else
        EV_DETAIL<<"Expired BPDU"<<endl;
    delete frame;

    colorRootPorts();
}

void RSTP::sendTCNtoRoot()
{
    // if TCWhile is not expired, sends BPDU with TC flag to the root
    this->bubble("SendTCNtoRoot");
    int r = getRootIndex();
    if ((r >= 0) && ((unsigned int) r < portCount))
    {
        Ieee8021DInterfaceData * rootPort = getPortInterfaceData(r);
        if (rootPort->getRole() != Ieee8021DInterfaceData::DISABLED)
        {
            if (simulation.getSimTime()<rootPort->getTCWhile())
            {
                BPDU * frame = new BPDU();
                Ieee802Ctrl * etherctrl= new Ieee802Ctrl();

                frame->setRootPriority(rootPort->getRootPriority());
                frame->setRootAddress(rootPort->getRootAddress());
                frame->setMessageAge(rootPort->getAge());
                frame->setRootPathCost(rootPort->getRootPathCost());
                frame->setBridgePriority(priority);
                frame->setTcaFlag(false);
                frame->setPortNum(r);
                frame->setBridgeAddress(address);
                frame->setTcFlag(true);
                frame->setName("BPDU");
                frame->setMaxAge(maxAge);
                frame->setHelloTime(hellotime);
                frame->setForwardDelay(fwdDelay);
                if (frame->getByteLength() < MIN_ETHERNET_FRAME_BYTES)
                frame->setByteLength(MIN_ETHERNET_FRAME_BYTES);
                etherctrl->setSrc(address);
                etherctrl->setDest(MACAddress::STP_MULTICAST_ADDRESS);
                etherctrl->setInterfaceId(r);
                frame->setControlInfo(etherctrl);
                send(frame,"relayOut");
            }
        }
    }
}

void RSTP::sendBPDUs()
{
    // send BPDUs through all ports, if they are required
    for (unsigned int i = 0; i < portCount; i++)
    {
        Ieee8021DInterfaceData * iPort = getPortInterfaceData(i);
        if ((iPort->getRole() != Ieee8021DInterfaceData::ROOT)
                && (iPort->getRole() != Ieee8021DInterfaceData::ALTERNATE)
                && (iPort->getRole() != Ieee8021DInterfaceData::DISABLED) && (!iPort->isEdge()))
        {
            sendBPDU(i);
        }
    }
}

void RSTP::sendBPDU(int port)
{
    // send a BPDU throuth port
    Ieee8021DInterfaceData * iport = getPortInterfaceData(port);
    int r = getRootIndex();
    Ieee8021DInterfaceData * rootPort;
    if (r != -1)
        rootPort = getPortInterfaceData(r);
    if (iport->getRole() != Ieee8021DInterfaceData::DISABLED)
    {
        BPDU * frame = new BPDU();
        Ieee802Ctrl * etherctrl = new Ieee802Ctrl();
        if (r != -1)
        {
            frame->setRootPriority(rootPort->getRootPriority());
            frame->setRootAddress(rootPort->getRootAddress());
            frame->setMessageAge(rootPort->getAge());
            frame->setRootPathCost(rootPort->getRootPathCost());
        }
        else
        {
            frame->setRootPriority(priority);
            frame->setRootAddress(address);
            frame->setMessageAge(0);
            frame->setRootPathCost(0);
        }
        frame->setBridgePriority(priority);
        frame->setTcaFlag(false);
        frame->setPortNum(port);
        frame->setBridgeAddress(address);
        if (simulation.getSimTime() < iport->getTCWhile())
        frame->setTcFlag(true);
        else
        frame->setTcFlag(false);
        frame->setName("BPDU");
        frame->setMaxAge(maxAge);
        frame->setHelloTime(hellotime);
        frame->setForwardDelay(fwdDelay);
        if (frame->getByteLength() < MIN_ETHERNET_FRAME_BYTES)
            frame->setByteLength(MIN_ETHERNET_FRAME_BYTES);
        etherctrl->setSrc(address);
        etherctrl->setDest(MACAddress::STP_MULTICAST_ADDRESS);
        etherctrl->setInterfaceId(port);
        frame->setControlInfo(etherctrl);
        send(frame, "relayOut");
    }
}

void RSTP::colorLink(unsigned int i, const char *color, unsigned int width)
{
    if (ev.isGUI() && treeColoring)
    {
        cGate * outGate = getParentModule()->gate("ethg$o", i);
        cGate * inputGate = getParentModule()->gate("ethg$i", i);
        cGate * outGateNext = outGate->getNextGate();
        cGate * inputGatePrev = inputGate->getPreviousGate();

        if (outGate && inputGate && inputGatePrev && outGateNext)
        {
            outGate->getDisplayString().setTagArg("ls", 0, color);
            outGate->getDisplayString().setTagArg("ls", 1, width);

            inputGate->getDisplayString().setTagArg("ls", 0, color);
            inputGate->getDisplayString().setTagArg("ls", 1, width);

            outGateNext->getDisplayString().setTagArg("ls", 0, color);
            outGateNext->getDisplayString().setTagArg("ls", 1, width);

            inputGatePrev->getDisplayString().setTagArg("ls", 0, color);
            inputGatePrev->getDisplayString().setTagArg("ls", 1, width);
        }
    }
}

void RSTP::colorRootPorts()
{
    if (ev.isGUI() && treeColoring)
    {
        Ieee8021DInterfaceData * port;
        // gives color to the root link, or module border if it is root
        for (unsigned int i = 0; i < portCount; i++)
        {
            port = getPortInterfaceData(i);
            if (port->getRole() == Ieee8021DInterfaceData::ROOT)
                colorLink(i, "#a5ffff", 3);

            cModule * puerta = this->getParentModule()->getSubmodule("eth", i);
            if (puerta != NULL)
            {
                char buf[25];
                char sbuf[12];
                char rbuf[13];

                int role = port->getRole();
                switch (role)
                {
                    case 0:
                        sprintf(rbuf, "ALTERNATE\n");
                        break;
                    case 1:
                        sprintf(rbuf, "NOTASSIGNED\n");
                        break;
                    case 2:
                        sprintf(rbuf, "DISABLED\n");
                        break;
                    case 3:
                        sprintf(rbuf, "DESIGNATED\n");
                        break;
                    case 4:
                        sprintf(rbuf, "BACKUP\n");
                        break;
                    case 5:
                        sprintf(rbuf, "ROOT\n");
                        break;
                    default:
                        sprintf(rbuf, "UNKNOWN\n");
                        break;
                }

                int state = port->getState();
                switch (state)
                {
                    case 0:
                        sprintf(sbuf, "DISCARDING\n");
                        break;
                    case 1:
                        sprintf(sbuf, "LEARNING\n");
                        break;
                    case 2:
                        sprintf(sbuf, "FORWARDING\n");
                        break;
                    default:
                        sprintf(sbuf, "UNKNOWN\n");
                        break;
                }

                sprintf(buf, "%s%s", rbuf, sbuf);
                puerta->getDisplayString().setTagArg("t", 0, buf);
            }
        }

        if (isOperational) //only when the router is working
        {
            if (getRootIndex() == -1)
            {
                // root mark
                this->getParentModule()->getDisplayString().setTagArg("i", 1, "#a5ffff");
            }
            else
            {
                // remove possible root mark
                this->getParentModule()->getDisplayString().setTagArg("i", 1, "");
            }
        }
    }
}

void RSTP::printState()
{
    //  prints current database info
    EV_DETAIL<<endl<<this->getParentModule()->getName()<<endl;
    int r=getRootIndex();
    EV_DETAIL<<"RSTP state"<<endl;
    EV_DETAIL<<"Priority: "<<priority<<endl;
    EV_DETAIL<<"Local MAC: "<<address<<endl;
    if(r>=0)
    {
        Ieee8021DInterfaceData * rootPort = getPortInterfaceData(r);
        EV_DETAIL<<"Root Priority: "<<rootPort->getRootPriority()<<endl;
        EV_DETAIL<<"Root address: "<<rootPort->getRootAddress().str()<<endl;
        EV_DETAIL<<"cost: "<<rootPort->getRootPathCost()<<endl;
        EV_DETAIL<<"age:  "<<rootPort->getAge()<<endl;
        EV_DETAIL<<"Bridge priority: "<<rootPort->getBridgePriority()<<endl;
        EV_DETAIL<<"Bridge address: "<<rootPort->getBridgeAddress().str()<<endl;
        EV_DETAIL<<"Src TxGate Priority: "<<rootPort->getPortPriority()<<endl;
        EV_DETAIL<<"Src TxGate: "<<rootPort->getPortNum()<<endl;
    }
    EV_DETAIL<<"Port State/Role: "<<endl;
    for(unsigned int i=0;i<portCount;i++)
    {
        Ieee8021DInterfaceData * iPort = getPortInterfaceData(i);
        EV_DETAIL<<iPort->getState()<<" ";
        if(iPort->getState() == Ieee8021DInterfaceData::DISCARDING)
        EV_DETAIL<<"Discarding";
        else if (iPort->getState() == Ieee8021DInterfaceData::LEARNING)
        EV_DETAIL<<"Learning";
        else if (iPort->getState() == Ieee8021DInterfaceData::FORWARDING)
        EV_DETAIL<<"Forwarding";
        EV_DETAIL<<"  ";
        if(iPort->getRole() == Ieee8021DInterfaceData::ROOT)
        EV_DETAIL<<"Root";
        else if (iPort->getRole() == Ieee8021DInterfaceData::DESIGNATED)
        EV_DETAIL<<"Designated";
        else if (iPort->getRole() == Ieee8021DInterfaceData::BACKUP)
        EV_DETAIL<<"Backup";
        else if (iPort->getRole() == Ieee8021DInterfaceData::ALTERNATE)
        EV_DETAIL<<"Alternate";
        else if (iPort->getRole() == Ieee8021DInterfaceData::DISABLED)
        EV_DETAIL<<"Disabled";
        else if (iPort->getRole() == Ieee8021DInterfaceData::NOTASSIGNED)
        EV_DETAIL<<"Not assigned";
        if(iPort->isEdge())
        EV_DETAIL<<" (Client)";
        EV_DETAIL<<endl;
    }
    EV_DETAIL<<"Per port best source. Root/Src"<<endl;
    for(unsigned int i=0;i<portCount;i++)
    {
        Ieee8021DInterfaceData * iPort = getPortInterfaceData(i);
        EV_DETAIL<<i<<" "<<iPort->getRootAddress().str()<<"/"<<iPort->getBridgeAddress().str()<<endl;
    }
}

void RSTP::initInterfacedata(unsigned int portNum)
{
    Ieee8021DInterfaceData * ifd = getPortInterfaceData(portNum);
    ifd->setRootPriority(priority);
    ifd->setRootAddress(address);
    ifd->setRootPathCost(0);
    ifd->setAge(0);
    ifd->setBridgePriority(priority);
    ifd->setBridgeAddress(address);
    ifd->setPortPriority(-1);
    ifd->setPortNum(-1);
    ifd->setLostBPDU(0);
}

void RSTP::initPorts()
{
    for (unsigned int j = 0; j < portCount; j++)
    {
        Ieee8021DInterfaceData * jPort = getPortInterfaceData(j);
        if (!jPort->isEdge())
        {
            jPort->setRole(Ieee8021DInterfaceData::NOTASSIGNED);
            jPort->setState(Ieee8021DInterfaceData::DISCARDING);
        }
        else
        {
            jPort->setRole(Ieee8021DInterfaceData::DESIGNATED);
            jPort->setState(Ieee8021DInterfaceData::FORWARDING);
        }
        initInterfacedata(j);
        macTable->flush(j);
    }
}

void RSTP::updateInterfacedata(BPDU *frame, unsigned int portNum)
{
    Ieee8021DInterfaceData * ifd = getPortInterfaceData(portNum);
    ifd->setRootPriority(frame->getRootPriority());
    ifd->setRootAddress(frame->getRootAddress());
    ifd->setRootPathCost(frame->getRootPathCost() + ifd->getLinkCost());
    ifd->setAge(frame->getMessageAge() + 1);
    ifd->setBridgePriority(frame->getBridgePriority());
    ifd->setBridgeAddress(frame->getBridgeAddress());
    ifd->setPortPriority(frame->getPortPriority());
    ifd->setPortNum(frame->getPortNum());
    ifd->setLostBPDU(0);
}
int RSTP::contestInterfacedata(unsigned int portNum)
{
    int r = getRootIndex();
    Ieee8021DInterfaceData * rootPort = getPortInterfaceData(r);
    Ieee8021DInterfaceData * ifd = getPortInterfaceData(portNum);

    int rootPriority1 = rootPort->getRootPriority();
    MACAddress rootAddress1 = rootPort->getRootAddress();
    int rootPathCost1 = rootPort->getRootPathCost() + ifd->getLinkCost();
    int bridgePriority1 = priority;
    MACAddress bridgeAddress1 = address;
    int portPriority1 = ifd->getPortPriority();
    int portNum1 = portNum;

    int rootPriority2 = ifd->getRootPriority();
    MACAddress rootAddress2 = ifd->getRootAddress();
    int rootPathCost2 = ifd->getRootPathCost();
    int bridgePriority2 = ifd->getBridgePriority();
    MACAddress bridgeAddress2 = ifd->getBridgeAddress();
    int portPriority2 = ifd->getPortPriority();
    int portNum2 = ifd->getPortNum();

    if (rootPriority1 != rootPriority2)
        return (rootPriority1 < rootPriority2) ? -1 : 1;

    int c = rootAddress1.compareTo(rootAddress2);
    if (c != 0)
        return (c < 0) ? -1 : 1;

    if (rootPathCost1 != rootPathCost2)
        return (rootPathCost1 < rootPathCost2) ? -2 : 2;

    if (bridgePriority1 != bridgePriority2)
        return (bridgePriority1 < bridgePriority2) ? -3 : 3;

    c = bridgeAddress1.compareTo(bridgeAddress2);
    if (c != 0)
        return (c < 0) ? -3 : 3;

    if (portPriority1 != portPriority2)
        return (portPriority1 < portPriority2) ? -4 : 4;

    if (portNum1 != portNum2)
        return (portNum1 < portNum2) ? -4 : 4;

    return 0;
}

int RSTP::contestInterfacedata(BPDU* msg, unsigned int portNum)
{
    int r = getRootIndex();
    Ieee8021DInterfaceData * rootPort = getPortInterfaceData(r);
    Ieee8021DInterfaceData * ifd = getPortInterfaceData(portNum);

    int rootPriority1 = rootPort->getRootPriority();
    MACAddress rootAddress1 = rootPort->getRootAddress();
    int rootPathCost1 = rootPort->getRootPathCost();
    int bridgePriority1 = priority;
    MACAddress bridgeAddress1 = address;
    int portPriority1 = ifd->getPortPriority();
    int portNum1 = portNum;

    int rootPriority2 = msg->getRootPriority();
    MACAddress rootAddress2 = msg->getRootAddress();
    int rootPathCost2 = msg->getRootPathCost();
    int bridgePriority2 = msg->getBridgePriority();
    MACAddress bridgeAddress2 = msg->getBridgeAddress();
    int portPriority2 = msg->getPortPriority();
    int portNum2 = msg->getPortNum();

    if (rootPriority1 != rootPriority2)
        return (rootPriority1 < rootPriority2) ? -1 : 1;

    int c = rootAddress1.compareTo(rootAddress2);
    if (c != 0)
        return (c < 0) ? -1 : 1;

    if (rootPathCost1 != rootPathCost2)
        return (rootPathCost1 < rootPathCost2) ? -2 : 2;

    if (bridgePriority1 != bridgePriority2)
        return (bridgePriority1 < bridgePriority2) ? -3 : 3;

    c = bridgeAddress1.compareTo(bridgeAddress2);
    if (c != 0)
        return (c < 0) ? -3 : 3;

    if (portPriority1 != portPriority2)
        return (portPriority1 < portPriority2) ? -4 : 4;

    if (portNum1 != portNum2)
        return (portNum1 < portNum2) ? -4 : 4;

    return 0;

}
int RSTP::compareInterfacedata(unsigned int portNum, BPDU * msg, int linkCost)
{
    Ieee8021DInterfaceData * ifd = getPortInterfaceData(portNum);

    int rootPriority1 = ifd->getRootPriority();
    MACAddress rootAddress1 = ifd->getRootAddress();
    int rootPathCost1 = ifd->getRootPathCost();
    int bridgePriority1 = ifd->getBridgePriority();
    MACAddress bridgeAddress1 = ifd->getBridgeAddress();
    int portPriority1 = ifd->getPortPriority();
    int portNum1 = ifd->getPortNum();

    int rootPriority2 = msg->getRootPriority();
    MACAddress rootAddress2 = msg->getRootAddress();
    int rootPathCost2 = msg->getRootPathCost() + linkCost;
    int bridgePriority2 = msg->getBridgePriority();
    MACAddress bridgeAddress2 = msg->getBridgeAddress();
    int portPriority2 = msg->getPortPriority();
    int portNum2 = msg->getPortNum();

    if (rootPriority1 != rootPriority2)
        return (rootPriority1 < rootPriority2) ? -1 : 1;

    int c = rootAddress1.compareTo(rootAddress2);
    if (c != 0)
        return (c < 0) ? -1 : 1;

    if (rootPathCost1 != rootPathCost2)
        return (rootPathCost1 < rootPathCost2) ? -2 : 2;

    if (bridgePriority1 != bridgePriority2)
        return (bridgePriority1 < bridgePriority2) ? -3 : 3;

    c = bridgeAddress1.compareTo(bridgeAddress2);
    if (c != 0)
        return (c < 0) ? -3 : 3;

    if (portPriority1 != portPriority2)
        return (portPriority1 < portPriority2) ? -4 : 4;

    if (portNum1 != portNum2)
        return (portNum1 < portNum2) ? -4 : 4;

    return 0;
}

int RSTP::getRootIndex()
{
    int result = -1;
    for (unsigned int i = 0; i < portCount; i++)
    {
        Ieee8021DInterfaceData * iPort = getPortInterfaceData(i);
        if (iPort->getRole() == Ieee8021DInterfaceData::ROOT)
        {
            result = i;
            break;
        }
    }
    return result;
}

int RSTP::getBestAlternate()
{
    int candidato = -1;  // index of the best alternate found
    for (unsigned int j = 0; j < portCount; j++)
    {
        Ieee8021DInterfaceData * jPort = getPortInterfaceData(j);
        if (jPort->getRole() == Ieee8021DInterfaceData::ALTERNATE) // just from alternates, others are not updated
        {
            if (candidato < 0)
                candidato = j;
            else
            {
                Ieee8021DInterfaceData * candidatoPort = getPortInterfaceData(candidato);
                if ((jPort->getRootPathCost() < candidatoPort->getRootPathCost())
                        || (jPort->getRootPathCost() == candidatoPort->getRootPathCost()
                                && jPort->getBridgePriority() < candidatoPort->getBridgePriority())
                        || (jPort->getRootPathCost() == candidatoPort->getRootPathCost()
                                && jPort->getBridgePriority() == candidatoPort->getBridgePriority()
                                && jPort->getBridgeAddress().compareTo(candidatoPort->getBridgeAddress()) < 0)
                        || (jPort->getRootPathCost() == candidatoPort->getRootPathCost()
                                && jPort->getBridgePriority() == candidatoPort->getBridgePriority()
                                && jPort->getBridgeAddress().compareTo(candidatoPort->getBridgeAddress()) == 0
                                && jPort->getPortPriority() < candidatoPort->getPortPriority())
                        || (jPort->getRootPathCost() == candidatoPort->getRootPathCost()
                                && jPort->getBridgePriority() == candidatoPort->getBridgePriority()
                                && jPort->getBridgeAddress().compareTo(candidatoPort->getBridgeAddress()) == 0
                                && jPort->getPortPriority() == candidatoPort->getPortPriority()
                                && jPort->getPortNum() < candidatoPort->getPortNum()))
                {
                    // alternate better than the found one
                    candidato = j; // new candidate
                }
            }
        }
    }
    return candidato;
}

void RSTP::start()
{
    initPorts();
    scheduleAt(simTime(), helloM);
    scheduleAt(simTime() + fwdDelay, forwardM);
    scheduleAt(simTime() + migrateTime, migrateM);
    isOperational = true;
}

void RSTP::stop()
{
    cancelEvent(helloM);
    cancelEvent(forwardM);
    cancelEvent(migrateM);
    isOperational = false;
}

bool RSTP::handleOperationStage(LifecycleOperation *operation, int stage, IDoneCallback *doneCallback)
{
    Enter_Method_Silent
    ();

    if (dynamic_cast<NodeStartOperation *>(operation))
    {
        if (stage == NodeStartOperation::STAGE_LINK_LAYER)
        {
            start();
        }
    }
    else if (dynamic_cast<NodeShutdownOperation *>(operation))
    {
        if (stage == NodeShutdownOperation::STAGE_LINK_LAYER)
        {
            stop();
        }
    }
    else if (dynamic_cast<NodeCrashOperation *>(operation))
    {
        if (stage == NodeCrashOperation::STAGE_CRASH)
        {
            stop();
        }
    }
    else
    {
        throw cRuntimeError("Unsupported operation '%s'", operation->getClassName());
    }

    return true;
}

Ieee8021DInterfaceData * RSTP::getPortInterfaceData(unsigned int portNum)
{
    cGate * gate = this->getParentModule()->gate("ethg$o", portNum);
    if (!gate)
        error("gate is NULL");
    InterfaceEntry * gateIfEntry = ifTable->getInterfaceByNodeOutputGateId(gate->getId());
    if (!gateIfEntry)
        error("gateIfEntry is NULL");
    Ieee8021DInterfaceData * portData = gateIfEntry->ieee8021DData();
    if (!portData)
        error("IEEE8021DInterfaceData not found!");

    return portData;
}
