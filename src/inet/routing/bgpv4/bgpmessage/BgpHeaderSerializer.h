//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

#ifndef INET_ROUTING_BGPV4_BGPMESSAGE_BGPHEADERSERIALIZER_H_
#define INET_ROUTING_BGPV4_BGPMESSAGE_BGPHEADERSERIALIZER_H_


#include "inet/common/packet/serializer/FieldsChunkSerializer.h"

namespace inet {
namespace bgp {

/**
 * Converts between BgpHeader and binary (network byte order) BGP messages.
 */
class INET_API BgpHeaderSerializer : public FieldsChunkSerializer
{
  protected:
    virtual void serialize(MemoryOutputStream& stream, const Ptr<const Chunk>& chunk) const override;
    virtual const Ptr<Chunk> deserialize(MemoryInputStream& stream) const override;

  public:
    BgpHeaderSerializer() : FieldsChunkSerializer() {}
};

} // namespace bgp
} // namespace inet


#endif /* INET_ROUTING_BGPV4_BGPMESSAGE_BGPHEADERSERIALIZER_H_ */
