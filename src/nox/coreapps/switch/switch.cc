 /*// us file is part of NOX.
 *
 * NOX is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * NOX is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NOX.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <boost/bind.hpp>
#include <boost/foreach.hpp>
#include <boost/shared_array.hpp>
#include <cstring>
#include <netinet/in.h>
#include <stdexcept>
#include <stdint.h>
#include <endian.h>

#include "openflow-default.hh"
#include "assert.hh"
#include "component.hh"
#include "flow.hh"
#include "fnv_hash.hh"
#include "hash_set.hh"
#include "ofp-msg-event.hh"
#include "vlog.hh"
#include "flowmod.hh"
#include "datapath-join.hh"
#include "datapath-leave.hh"
#include "packets.h"
#include <stdio.h>
#include <vector>
#include <map>
#include <queue>
#include <set>

#include <stdio.h>
#include "netinet++/ethernetaddr.hh"
#include "netinet++/ethernet.hh"
#include "netinet++/ip.hh"

#include "../../../oflib/ofl-actions.h"
#include "../../../oflib/ofl-messages.h"

using namespace vigil;
using namespace vigil::container;
using namespace std;

namespace {

struct Datapath
{
    //port, port_mac
    std::map<int, ethernetaddr> ports;
    //dpid, port_out, koszt
    std::map<datapathid, std::pair<int,int> > links;
    //mac_in, port_in
    std::map<ethernetaddr, int> sources;
    //koszt
    int weight;
};

struct node
{
	datapathid dpid;
	int weight;

	node(int weight_)
		: dpid(datapathid()), weight(weight_)
	{ }
	node(datapathid dpid_, int weight_)
		: dpid(dpid_), weight(weight_)
	{ }
	node()
	{ }
};

class GreaterNode {
	public:
	bool const operator()(node &nodeA, node &nodeB) {
		return (nodeA.weight > nodeB.weight);
	}
};

Vlog_module log("switch");
class Switch
    : public Component
{
public:
    Switch(const Context* c,
           const json_object*)
        : Component(c) { }

    void configure(const Configuration*);

    void install();

    Disposition handle_port(const Event&);
    Disposition handle(const Event&);
    Disposition handle_dp_join(const Event& e);
    Disposition handle_dp_leave(const Event& e);

private:
    bool macSource(ethernetaddr eth);
    bool macInPorts(ethernetaddr eth, datapathid dpid, int in_port);
    datapathid dpFromMac(ethernetaddr eth);
    vector<datapathid> edgeDpFromMac(ethernetaddr eth);

    typedef std::pair<ipaddr, ipaddr> ipPair;
    typedef std::set<node, GreaterNode> nodeSet;
    typedef std::map<ipPair, int> ipQueue;
    typedef std::map<datapathid, node> Switch_weight;
    typedef std::map<datapathid, Switch_weight> Distances;
    typedef std::map<datapathid, Datapath> Topology;
    typedef std::map<ipaddr, ethernetaddr> HostMap;
    typedef std::priority_queue<node, std::vector<node>, GreaterNode> Node_queue;

    Topology topo;
    Distances dstNodes;
    HostMap hosts;
    ethernetaddr gateway;
    ipQueue ipq;

    int timecnt;
    uint32_t controllerID;
};

void
Switch::configure(const Configuration* conf) {

    timecnt = 0;
    controllerID = 1;
    gateway = ethernetaddr("aa:aa:aa:aa:aa:ff");
    BOOST_FOREACH (const std::string& arg, conf->get_arguments()) {
        if (arg == "two") {
           controllerID = 2;
        } else {
            VLOG_WARN(log, "argument \"%s\" not supported", arg.c_str());
        }
    }
    // mapa hostow ip2mac, uproszczenie, mozliwe jest wyciagniecie tego przez dhcp,
    // poza zakresem projektu
    hosts.insert(std::pair<ipaddr,ethernetaddr>(ipaddr(167772426), ethernetaddr("aa:aa:aa:aa:aa:01")));
    hosts.insert(std::pair<ipaddr,ethernetaddr>(ipaddr(167772436), ethernetaddr("aa:aa:aa:aa:aa:02")));
    hosts.insert(std::pair<ipaddr,ethernetaddr>(ipaddr(167772446), ethernetaddr("aa:aa:aa:aa:aa:03")));
    hosts.insert(std::pair<ipaddr,ethernetaddr>(ipaddr(167772456), ethernetaddr("aa:aa:aa:aa:aa:04")));
    hosts.insert(std::pair<ipaddr,ethernetaddr>(ipaddr(167772466), ethernetaddr("aa:aa:aa:aa:aa:05")));
    hosts.insert(std::pair<ipaddr,ethernetaddr>(ipaddr(167772476), ethernetaddr("aa:aa:aa:aa:aa:06")));

    register_handler(Datapath_join_event::static_get_name(), boost::bind(&Switch::handle_dp_join, this, _1));
    register_handler(Datapath_leave_event::static_get_name(), boost::bind(&Switch::handle_dp_leave, this, _1));
    register_handler(Ofp_msg_event::get_name(OFPT_PACKET_IN), boost::bind(&Switch::handle, this, _1));
    register_handler(Ofp_msg_event::get_stats_name(OFPMP_PORT_DESC), boost::bind(&Switch::handle_port, this, _1));
}

void
Switch::install() {

}

Disposition
Switch::handle_dp_join(const Event& e) {

    const Datapath_join_event& dpj = assert_cast<const Datapath_join_event&>(e);
    Datapath dp;
    dp.weight = 1;
    topo.insert(std::pair<datapathid, Datapath>(dpj.dpid, dp));
    // dodanie domyslnego flow przekierowujacego pakiety miss do kontrolera
    Flow  *f = new Flow();

    Actions *acts = new Actions();
    acts->CreateOutput(OFPP_CONTROLLER, 40);
    Instruction *inst =  new Instruction();
    inst->CreateApply(acts);
    FlowMod *mod = new FlowMod(0x00ULL,0x00ULL, 0, OFPFC_ADD, OFP_FLOW_PERMANENT,
	OFP_FLOW_PERMANENT, 0, 0, OFPP_ANY, OFPG_ANY, ofd_flow_mod_flags());
    mod->AddMatch(&f->match);
    mod->AddInstructions(inst);
    send_openflow_msg(dpj.dpid, (struct ofl_msg_header *)&mod->fm_msg, 0, true);
	// hack do tworzenia port_desc requesta i wysylanie go do kazdego switcha
	// ktory sie przedstawia - od razu dostajemy info o portach dostepnych
	// powinno byc ladnie tworzone w ramach jakiejs zewnetrznej klasy, alas.
    ofl_msg_multipart_request_header mrh_msg;
    mrh_msg.type = OFPMP_PORT_DESC;
    mrh_msg.flags = 0x0000;
    mrh_msg.header.type = OFPT_MULTIPART_REQUEST;
    send_openflow_msg(dpj.dpid, (struct ofl_msg_header *)&mrh_msg ,0, true);

    return CONTINUE;
}

Disposition
Switch::handle_dp_leave(const Event& e){

    const Datapath_leave_event& dpl = assert_cast<const Datapath_leave_event&>(e);
}


Disposition
Switch::handle_port(const Event& e){

    const Ofp_msg_event& pd = assert_cast<const Ofp_msg_event&>(e);
	// handling multipart msg z port_desc!!
    struct ofl_msg_multipart_reply_port_desc *desc = (struct ofl_msg_multipart_reply_port_desc *)**pd.msg;
    for(int i=0; i<desc->stats_num; i++){
	//dodanie portu do listy portow w mapie topologii
	Port *port = new Port((struct ofl_port*) desc->stats[i]);
	if(port->port_no != -2) {
	// Dodanie portu do listy portow w przelaczniku
		map<int,ethernetaddr>::iterator i(topo[pd.dpid].ports.find(port->port_no));
		if ( i == topo[pd.dpid].ports.end()){
			topo[pd.dpid].ports.insert(std::pair<int,ethernetaddr>(port->port_no,port->hw_addr));
		}
    	}
    }
    //duzy dodatkowy ruch, ale rozeslane sa dodatkowe LLDP na wszystkie switche w sieci
    //pomaga w mapowaniu
    for(Topology::iterator i=topo.begin(); i!=topo.end(); i++){
	for(map<int,ethernetaddr>::iterator j=i->second.ports.begin(); j!=i->second.ports.end(); j++){
		uint8_t *lldp = new uint8_t[36];
		uint64_t dpid = i->first.as_net();
		struct eth_header *eth = (struct eth_header *)lldp;
		// Tworzenie LLDP - logika etc
		memcpy(eth->eth_src, &j->second, 6);
		memset(eth->eth_src, 0x00, 1);
		// switch okreslajac przynaleznosc do kontrolera TBD
//		if(controllerID == 1){
			memcpy(eth->eth_dst, "\01\23\20\00\00\01", 6);
//		}
//		else{
//			memcpy(eth->eth_dst, "\01\23\20\00\00\02", 6);
//		}
		eth->eth_type = htons(0x88cc);

		uint8_t *chassis_tlv = lldp+14;
		memcpy(chassis_tlv, "\02\07", 2);
		memcpy(chassis_tlv+2, "\04", 1);
		memcpy(chassis_tlv+3, ((uint8_t *)&dpid)+2, 6);

		uint8_t *port_tlv = chassis_tlv+9;
		memcpy(port_tlv, "\04\05", 2);
		memcpy(port_tlv+2, "\02", 1);
		memcpy(port_tlv+3, &j->first, 4);

		uint8_t *ttl_tlv = port_tlv + 7;
		memcpy(ttl_tlv, "\06\02", 2);
		memcpy(ttl_tlv+2, "\00\02", 2);

		uint8_t *end_tlv = ttl_tlv +4;
		memset(end_tlv, 0x00, 2);

		send_openflow_pkt(i->first, Array_buffer(lldp, 36), OFPP_CONTROLLER, j->first, true);
		// debug only
		//VLOG_DBG(log, "sent pkt to dpid %s, on port %d, "EA_FMT"", (*i).datapath_id.string().c_str(), (*i).port_id, EA_ARGS(&(*i).mac));
		//VLOG_DBG(log, "count %d", ports.size());
    	}
    }
    //debug log, obsolete
    //VLOG_DBG(log, "Port_Desc received: count %d, dpid: %s", desc->stats_num, pd.dpid.string().c_str());
    return CONTINUE;
}

Disposition
Switch::handle(const Event& e){

    const Ofp_msg_event& pi = assert_cast<const Ofp_msg_event&>(e);
    timecnt++;
    struct ofl_msg_packet_in *in = (struct ofl_msg_packet_in *)**pi.msg;
    Flow *flow = new Flow((struct ofl_match*) in->match);

        uint16_t dl_type;
        flow->get_Field<uint16_t>("eth_type",&dl_type);
	if (dl_type == ethernet::IPV6 || dl_type == htons_<0xdd86>::val){

	}
    	if (dl_type == ethernet::ARP){
//		VLOG_DBG(log, "ARP detected");
	}
	if (dl_type == htons_<0x0608>::val){
//		VLOG_DBG(log, "ARP, bytes reversed!!");
	}
	if (dl_type == ethernet::REVARP){
//		VLOG_DBG(log, "REVARP detected");
	}
    //	VLOG_DBG(log, "EthType - <%d>", htons(dl_type));

   if(timecnt == 100){
    for(Topology::iterator i=topo.begin(); i!=topo.end(); i++){
	for(map<int,ethernetaddr>::iterator j=i->second.ports.begin(); j!=i->second.ports.end(); j++){
		uint8_t *lldp = new uint8_t[36];
		uint64_t dpid = i->first.as_net();
		struct eth_header *eth = (struct eth_header *)lldp;
		// Tworzenie LLDP - logika etc
		memcpy(eth->eth_src, &j->second, 6);
		memset(eth->eth_src, 0x00, 1);
		// switch okreslajac przynaleznosc do kontrolera TBD
//		if(controllerID == 1){
			memcpy(eth->eth_dst, "\01\23\20\00\00\02", 6);
//		}
//		else{
//			memcpy(eth->eth_dst, "\01\23\20\00\00\02", 6);
//		}
		eth->eth_type = htons(0x88cc);

		uint8_t *chassis_tlv = lldp+14;
		memcpy(chassis_tlv, "\02\07", 2);
		memcpy(chassis_tlv+2, "\04", 1);
		memcpy(chassis_tlv+3, ((uint8_t *)&dpid)+2, 6);

		uint8_t *port_tlv = chassis_tlv+9;
		memcpy(port_tlv, "\04\05", 2);
		memcpy(port_tlv+2, "\02", 1);
		memcpy(port_tlv+3, &j->first, 4);

		uint8_t *ttl_tlv = port_tlv + 7;
		memcpy(ttl_tlv, "\06\02", 2);
		memcpy(ttl_tlv+2, "\00\02", 2);

		uint8_t *end_tlv = ttl_tlv +4;
		memset(end_tlv, 0x00, 2);

		send_openflow_pkt(i->first, Array_buffer(lldp, 36), OFPP_CONTROLLER, j->first, true);
		// debug only
		//VLOG_DBG(log, "sent pkt to dpid %s, on port %d, "EA_FMT"", (*i).datapath_id.string().c_str(), (*i).port_id, EA_ARGS(&(*i).mac));
		//VLOG_DBG(log, "count %d", ports.size());
    	}
    }

    timecnt = 0;
    }


    uint32_t in_port;
    flow->get_Field<uint32_t>("in_port", &in_port);
    if(in_port == -2) {
	return STOP;
    }

    uint8_t eth_src[6];
    uint8_t eth_dst[6];
    flow->get_Field("eth_src", eth_src);
    flow->get_Field("eth_dst", eth_dst);
    ethernetaddr dl_src(eth_src);
    ethernetaddr dl_dst(eth_dst);
    ethernetaddr edge("01:13:10:00:01:00");
    if (dl_type == ethernet::LLDP || dl_type == htons_<0xcc88>::val){
	// handling LLDP - hak na dodanie maca edge'a na switchach granicznych
	//VLOG_DBG(log, "dtp %d src "EA_FMT" dst "EA_FMT" ports.size %d", pi.dpid.as_host(), EA_ARGS(&dl_src), EA_ARGS(&dl_dst), topo[pi.dpid].ports.size());
	if(dl_dst == edge){
		dl_src = dl_dst;
//		VLOG_DBG(log, "x "EA_FMT", y "EA_FMT"", EA_ARGS(&dl_src), EA_ARGS(&dl_dst));
	}
//	return CONTINUE;
    }

    uint8_t iip_src[4];
    uint8_t iip_dst[4];
	// tu powinien byc if
    flow->get_Field("ipv4_src", iip_src);
    flow->get_Field("ipv4_dst", iip_dst);
    ipaddr ipSrc = ipaddr(iip_src);
    ipaddr ipDst = ipaddr(iip_dst);
	if (dl_type == ethernet::IP || dl_type == htons_<0x0008>::val){
		VLOG_DBG(log, "src %02x%02x%02x%02x, dst %02x%02x%02x%02x",
		iip_src[0] & 0xff, iip_src[1] & 0xff, iip_src[2] & 0xff, iip_src[3] & 0xff,
		iip_dst[0] & 0xff, iip_dst[1] & 0xff, iip_dst[2] & 0xff, iip_dst[3] & 0xff);

//		VLOG_DBG(log, "IPV4 detected");
	}

    // usuniecie pakietow ktore sa jakims cudem zwracane na loopback (odbijaja sie i wracaja
    // z source mac takim samym jak mac portu na ktory przyszly - nadmiarowe krawedzie)
    if (topo[pi.dpid].ports[in_port] == dl_src) {
	return STOP;
    }
	// dl_dst.is_multicast() usuwa cala komunikacje ipv6 nh, nie chcemy tego
    if ((!dl_src.is_multicast() || dl_src == edge) && dl_type != htons_<0x0008>::val) {
	map<ethernetaddr,int>::iterator i = topo[pi.dpid].sources.find(dl_src);
	if(i == topo[pi.dpid].sources.end()){
		topo[pi.dpid].sources.insert(std::pair<ethernetaddr, int>(dl_src,in_port));
            	VLOG_DBG(log, "learned that "EA_FMT" is on datapath %s port %d",
                	     EA_ARGS(&dl_src), pi.dpid.string().c_str(),
                     	(int) in_port);
		macInPorts(dl_src, pi.dpid, in_port);
	}
    }


    // cel i poczatek znajduja sie w naszej domenie
    // DIJKSTRA
    datapathid dp_src = dpFromMac(dl_src);

    // case z dst poza nasza domena, dst zamieniamy na edge w przypadku wysylania ruchu
    // na adres GW domeny
    if(dp_src != datapathid() && dl_dst == gateway){
	dl_dst = edge;
    }

    // wyciagniecie datapathid dla
    datapathid dp_dst = dpFromMac(dl_dst);


    bool direction = 0; // 0 - in, 1 - out
    bool edgeEnd = 0; // 0 - czekam na wiecej pakietow, 1 - dijkstra
    if(dl_type == htons_<0x0008>::val && hosts.count(ntohl(ipDst.addr)) != 0){
	ethernet *eh = (ethernet*)in->data;
	ip_ *ip = (ip_*)eh->data();
	uint8_t *payload = (uint8_t*)eh+34;
	// inicjacja - halturniczo
	if(ip->protocol == 253){
	 if( *((uint8_t*)(payload)) == 0){
		direction = 1;
		ipPair ipP = ipPair(ntohl(ipSrc.addr), ntohl(ipDst.addr));
		if(ipq.find(ipP) == ipq.end()){
			ipq.insert(std::pair<ipPair, int>(ipP, *((uint8_t*)(payload+1))));
			topo[pi.dpid].weight = *((uint8_t*)(payload+2));
			ipq[ipP]--;
			if(ipq[ipP] == 0){
				edgeEnd = 1;
				dp_src = dpFromMac(hosts[ntohl(ipDst.addr)]);
				dp_dst = pi.dpid;
				dl_dst = edge;
				dl_src = hosts[ntohl(ipDst.addr)];
				VLOG_DBG(log, "dp_src %s dp_dst %s", dp_src.string().c_str(), dp_dst.string().c_str());
			}
			else{
				return STOP;
			}

		}
		else{
			if(ipq[ipP] != 0){
				topo[pi.dpid].weight = *((uint8_t*)(payload+2));
				ipq[ipP]--;
				if(ipq[ipP] == 0){
					edgeEnd = 1;
					dp_src = dpFromMac(hosts[ntohl(ipDst.addr)]);
					dp_dst = pi.dpid;
					dl_dst = edge;
					dl_src = hosts[ntohl(ipDst.addr)];
					VLOG_DBG(log, "dp_src %s dp_dst %s", dp_src.string().c_str(), dp_dst.string().c_str());
				}
				else{
					return STOP;
				}
			}
			else{
				return STOP;
			}
		}
	 }
	 else{
		direction = 0;
		VLOG_DBG(log, "rev msg on %s", pi.dpid.string().c_str());
		edgeEnd = 1;
		dp_src = dpFromMac(hosts[ntohl(ipDst.addr)]);
		dp_dst = pi.dpid;
		dl_dst = edge;
		dl_src = hosts[ntohl(ipDst.addr)];
	 }
	}
    }
    vector<datapathid> edgeDp = edgeDpFromMac(dl_dst);

    // DIJKSTRA wlasciwa
    if(dp_src != datapathid() && dp_dst != datapathid() && dl_src != dl_dst){
	Switch_weight weights;
	Node_queue Q;
	node n;
	for(Topology::iterator i = topo.begin(); i!=topo.end(); i++){
		weights.insert(std::pair<datapathid, node>(i->first, node(INT_MAX)));
	}
	weights.at(dp_src).weight = 0;
	Q.push(node(dp_src, 0));
	while(!Q.empty()) {
		n = Q.top();
		Q.pop();
		if(n.weight <= weights[n.dpid].weight) {
			for(map<datapathid, std::pair<int, int> >::iterator i = topo[n.dpid].links.begin(); i!=topo[n.dpid].links.end(); i++) {
				if(weights[i->first].weight > weights[n.dpid].weight + i->second.second){
					weights[i->first].weight = weights[n.dpid].weight + i->second.second;
					weights[i->first].dpid = n.dpid;
					Q.push(node(i->first , weights[i->first].weight));
				}
			}
		}
	}
	dstNodes.insert(std::pair<datapathid, Switch_weight>(dp_src, weights));

	if(dl_type == htons_<0x0008>::val && hosts.count(ntohl(ipDst.addr)) == 0){
		VLOG_DBG(log, "src %02x%02x%02x%02x, dst %02x%02x%02x%02x",
		iip_src[0] & 0xff, iip_src[1] & 0xff, iip_src[2] & 0xff, iip_src[3] & 0xff,
		iip_dst[0] & 0xff, iip_dst[1] & 0xff, iip_dst[2] & 0xff, iip_dst[3] & 0xff);

		vector<datapathid>::iterator itEdge = edgeDp.begin();
		// wyslanie pakietu ipv4 z waga na punkcie styku
		for(itEdge; itEdge != edgeDp.end(); itEdge++){
			uint8_t *ip = new uint8_t[40];
			// Tworzenie IP - logika (brak)
			ethernet *eh = (ethernet*)ip;
			eh->daddr = dl_dst;
			eh->saddr = dl_src;
			eh->type = ethernet::IP;
			ip_ *ih = (ip_*)eh->data();
			ih->ihl = 5;
			ih->ver = 4;
			ih->tos = 0;
			ih->tot_len = htons(64 - sizeof(*eh));
			ih->id = htons(1234);
			ih->frag_off = 0;
			ih->ttl = ip_::DEFTTL;
			ih->protocol = 253;
			ih->csum = 0;
			ih->saddr = ipSrc.addr;
			ih->daddr = ipDst.addr;
			ih->csum = htons(ih->calc_csum());
			uint8_t *dir = ip+34;
			*dir = (uint8_t)0;
			uint8_t *cnt = dir+1;
			*cnt = (uint8_t)edgeDp.size();
			uint8_t *wght = cnt+1;
			*wght = (uint8_t)dstNodes[dp_src][*itEdge].weight;
			send_openflow_pkt(*itEdge, Array_buffer(ip, 40), OFPP_CONTROLLER, topo[*itEdge].sources[edge], false);
			VLOG_DBG(log,"dpid %s, port %d, ipsrc %d, ipdst %d", (*itEdge).string().c_str(), topo[*itEdge].sources[edge], ntohl(ipSrc.addr), ntohl(ipDst.addr));
		}
		return STOP;
    	}
	// mapa calej topologii i odleglosci od datapath (klucza) do kazdego innego dp
	// wraz z poprzednimi dp - wyjscia dijkstry dla poszczegolnych dp poczatkowych
	// dodawanie flow przekierowujacych pakiety z src do dst
	// dodatkowa logika w przypadku gdy dst = edge -> konieczne znalezienie najtanszej dp
	// wlasciwe wyznaczanie sciezki
	Flow f;
	Flow rf;
	if(hosts.count(ntohl(ipSrc.addr)) != 0 && hosts.count(ntohl(ipDst.addr)) != 0){
		f.Add_Field("eth_src", eth_src);
		f.Add_Field("eth_dst", eth_dst);
		rf.Add_Field("eth_src", eth_dst);
		rf.Add_Field("eth_dst", eth_src);
	}
	else{
		f.Add_Field("eth_type", 2048);
		f.Add_Field("ipv4_src", ipDst.addr);
		f.Add_Field("ipv4_dst", ipSrc.addr);
		rf.Add_Field("eth_type", 2048);
		rf.Add_Field("ipv4_dst", ipDst.addr);
		rf.Add_Field("ipv4_src", ipSrc.addr);
		VLOG_DBG(log, "src %02x%02x%02x%02x, dst %02x%02x%02x%02x",
		iip_src[0] & 0xff, iip_src[1] & 0xff, iip_src[2] & 0xff, iip_src[3] & 0xff,
		iip_dst[0] & 0xff, iip_dst[1] & 0xff, iip_dst[2] & 0xff, iip_dst[3] & 0xff);
		VLOG_DBG(log, "edge size %d, dp_dst %s, dp_src %s", edgeDp.size(), dp_dst.string().c_str(), dp_src.string().c_str());
		if(direction == 1){
			for(int x = 0; x<edgeDp.size(); x++){
				if(weights[edgeDp[x]].weight < weights[dp_dst].weight){
					dp_dst = edgeDp[x];
				}
			}
			VLOG_DBG(log, "min dp_dst %s", dp_dst.string().c_str());
			uint8_t *ip = new uint8_t[40];
			// Tworzenie IP - logika (brak)
			ethernet *eh = (ethernet*)ip;
			eh->daddr = dl_dst;
			eh->saddr = dl_src;
			eh->type = ethernet::IP;
			ip_ *ih = (ip_*)eh->data();
			ih->ihl = 5;
			ih->ver = 4;
			ih->tos = 0;
			ih->tot_len = htons(64 - sizeof(*eh));
			ih->id = htons(1234);
			ih->frag_off = 0;
			ih->ttl = ip_::DEFTTL;
			ih->protocol = 253;
			ih->csum = 0;
			ih->saddr = ipDst.addr;
			ih->daddr = ipSrc.addr;
			ih->csum = htons(ih->calc_csum());
			uint8_t *dir = ip+34;
			*dir = (uint8_t)1;
			uint8_t *cnt = dir+1;
			*cnt = (uint8_t)1;
			uint8_t *wght = cnt+1;
			*wght = (uint8_t)weights[dp_dst].weight;
			send_openflow_pkt(dp_dst, Array_buffer(ip, 40), OFPP_CONTROLLER, topo[dp_dst].sources[edge], false);
		}
	}
	datapathid dp_tmp = dp_dst;
	datapathid dp_tmp2 = dp_dst;
	datapathid rdp_tmp = dp_dst;
	for(int i=0; i< dstNodes[dp_src][dp_dst].weight+1; i++){
		int out_port;
		int rout_port;
		Actions *acts = new Actions();
		Instruction *inst = new Instruction();
		if(dp_tmp == dp_dst){
			out_port = topo[dp_tmp].sources[dl_dst];
		}
		else {
			out_port = topo[dp_tmp].links[dp_tmp2].first;
			int k = topo[dp_tmp].links.count(dp_tmp2);
			VLOG_DBG(log, "count %d", k);
			dp_tmp2 = dp_tmp;
		}
		if(dp_tmp == dp_src){
			rout_port = topo[dp_tmp].sources[dl_src];
		}
		else{
			rdp_tmp = dstNodes[dp_src][dp_tmp].dpid;
			rout_port = topo[dp_tmp].links[rdp_tmp].first;
		}
		acts->CreateOutput(out_port);
		inst->CreateApply(acts);
		FlowMod *mod = new FlowMod(0x00ULL, 0x00ULL, 0, OFPFC_ADD, OFP_FLOW_PERMANENT,
			OFP_FLOW_PERMANENT, 6, 0, OFPP_ANY, OFPG_ANY,
			ofd_flow_mod_flags());
		mod->AddMatch(&f.match);
		mod->AddInstructions(inst);
		send_openflow_msg(dp_tmp, (struct ofl_msg_header *)&mod->fm_msg, 0, true);
		VLOG_DBG(log, "Added flow to dpid %s, on port %d", dp_tmp.string().c_str(), out_port);

		Actions *racts = new Actions();
		Instruction *rinst = new Instruction();
		racts->CreateOutput(rout_port);
		rinst->CreateApply(racts);
		FlowMod *rmod = new FlowMod(0x00ULL, 0x00ULL, 0, OFPFC_ADD, OFP_FLOW_PERMANENT,
			OFP_FLOW_PERMANENT, 5, 0, OFPP_ANY, OFPG_ANY,
			ofd_flow_mod_flags());
		rmod->AddMatch(&rf.match);
		rmod->AddInstructions(rinst);
		send_openflow_msg(dp_tmp, (struct ofl_msg_header *)&rmod->fm_msg, 0, true);
		VLOG_DBG(log, "Added rflow to dpid %s, on port %d", dp_tmp.string().c_str(), rout_port);

		dp_tmp = dstNodes[dp_src][dp_tmp].dpid;
	}
    }


    return STOP;
}

bool
Switch::macSource(ethernetaddr eth){
	for(int k=0; k<topo.size(); k++){
			return true;
		k++;
	}
	return false;
}

bool
Switch::macInPorts(ethernetaddr eth, datapathid dpid,int in_port){

    for(Topology::iterator i = topo.begin(); i!=topo.end(); i++){
	for(map<int,ethernetaddr>::iterator j = i->second.ports.begin(); j!=i->second.ports.end(); j++){
		if(j->second == eth){
			topo[dpid].links.insert(std::pair<datapathid,std::pair<int,int> >(i->first,std::pair<int,int>(in_port,1)));
			return true;
		}
	}
    }
    return false;
}

datapathid
Switch::dpFromMac(ethernetaddr eth){
    for(Topology::iterator i = topo.begin(); i!=topo.end(); i++){
	for(map<ethernetaddr, int>::iterator j = i->second.sources.begin(); j!=i->second.sources.end(); j++){
		if(j->first == eth){
			return i->first;
		}
	}
    }
    return datapathid();
}

vector<datapathid>
Switch::edgeDpFromMac(ethernetaddr eth){
    vector<datapathid> out;
    for(Topology::iterator i = topo.begin(); i!=topo.end(); i++){
	for(map<ethernetaddr, int>::iterator j = i->second.sources.begin(); j!=i->second.sources.end(); j++){
		if(j->first == eth){
			out.push_back(i->first);
		}
	}
    }
    return out;
}

REGISTER_COMPONENT(container::Simple_component_factory<Switch>, Switch);

}
