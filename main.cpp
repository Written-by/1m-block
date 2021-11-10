#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <queue>

#include "libnet.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
using namespace std;

string host;
const int domain_char_size=38;
int MAX_DOMAIN_SIZE=0;

void usage()
{
    printf("syntax : 1m-block <site list file>\n");
    printf("sample : 1m-block top-1m.txt\n");
}

int get_key(const char&c){
	if('0'<=c&&c<='9') return c-'0';
	else if('A'<=c&&c<='Z') return c-'A'+10;
	else if('a'<=c&&c<='z') return c-'a'+10;
	else if(c=='-') return 36;
	else if(c=='.') return 37;
	else return -1;
}

class Trie{
private:
	vector<Trie*>child;
	Trie* fail;
	bool isEnd;
	string name;
public:
	Trie(){
		this->child.resize(domain_char_size,NULL);
		this->fail=NULL;
		this->isEnd=false;
		this->name="";
	}
	~Trie(){
		for(int i=0; i<domain_char_size; i++) if(child[i]) delete child[i];
	}
	Trie* get_fail(){
		return this->fail;
	}
	void set_fail(Trie* fail){
		this->fail=fail;
	}
	Trie* get_child(int i){
		return this->child[i];
	}
	bool get_isEnd(){
		return this->isEnd;
	}
	void set_isEnd(bool isEnd){
		this->isEnd=isEnd;
	}
	string get_name(){
		return this->name;
	}
	void set_name(string name){
		this->name=name;
	}
	void insert(const string &key, int ind){
		int nkey=get_key(key[ind]);
		if(nkey==-1){
			fprintf(stderr, "Invalid input\n");
			exit(1);
		}
		if(key.size()<ind){
			if(!child[nkey]) child[nkey]=new Trie;
			child[nkey]->insert(key, ind+1);
		}
		else{
			isEnd=true;
			name=key;
		}
	}
};

Trie*root;

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d\n", ret);

	fputc('\n', stdout);

	return id;
}

string check_blocked_site(const string& data){
	string host=data.substr(data.find("Host: ")+6);
	if(host.find("www.")!=string::npos) host=host.substr(host.find("www.")+4,MAX_DOMAIN_SIZE);
	else host=host.substr(0,MAX_DOMAIN_SIZE);
	Trie*now=root;
	for(char k:host){
		int next=get_key(k);
		if(next==-1){
			fprintf(stderr, "Invalid input\n");
			exit(1);
		}
		while(now!=root&&!(now->get_child(next))) now=now->get_child(next);
		if(now->get_isEnd()) return now->get_name();
	}
	return "";
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	u_char* packet;
	int packet_len=nfq_get_payload(nfa, &packet);
	int loc=0;
	if(packet_len>=0){
		struct libnet_ipv4_hdr* ip=(struct libnet_ipv4_hdr*)packet;
		if((ip->ip_p)!=6) goto pass;
		loc+=ip->ip_hl<<2;

		struct libnet_tcp_hdr* tcp=(struct libnet_tcp_hdr*)(packet+loc);
		if(ntohs(tcp->th_sport)!=80&&ntohs(tcp->th_dport)!=80) goto pass;
		loc+=tcp->th_off<<2;
		
		string data=(char*)(packet+loc);
		string domain=check_blocked_site(data);
		if(data.size()>0&&(data.find("GET")!=string::npos||data.find("POST")!=string::npos||data.find("PUT")!=string::npos||data.find("HEAD")!=string::npos||data.find("DELETE")!=string::npos||data.find("CONNECT")!=string::npos||data.find("OPTIONS")!=string::npos||data.find("TRACE")!=string::npos||data.find("PATCH")!=string::npos&&domain!="")){
			printf("DROP %s\n",domain.c_str());
			return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
		}
	}
	pass:
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if(argc!=2){
		usage();
		exit(1);
	}
	host=argv[1];
	
	root=new Trie;
	fstream domain_list;
	domain_list.open(host,ios::in);
	if(domain_list.fail()){
		perror("Error in opening file");
		exit(1);
	}
	while(domain_list.peek()!=EOF){
		string domain_block;
		getline(domain_list,domain_block);
		if(domain_block.find('\r')!=string::npos) domain_block=domain_block.substr(0, domain_block.find('\r'));
		if(domain_block.find('\n')!=string::npos) domain_block=domain_block.substr(0, domain_block.find('\n'));
		if(domain_block.find(',')==string::npos) continue;
		else{
			MAX_DOMAIN_SIZE=max(MAX_DOMAIN_SIZE,(int)domain_block.size());
			root->insert(domain_block.substr(domain_block.find(',')+1), 0);
			//root->insert(domain_block.substr(domain_block.find(',')+1, -1), 0);
		}
		printf("domain: %s\n",domain_block);
	}
	MAX_DOMAIN_SIZE+=10;

	queue<Trie*> que;
	root->set_fail(root);
	que.push(root);
	while(!que.empty()){
		Trie* now=que.front();
		que.pop();
		for(int i=0; i<domain_char_size; i++){
			Trie* next=now->get_child(i);
			if(!next) continue;
			else{
				Trie* anc=now->get_fail();
				while(anc!=root&&!(anc->get_child(i))){
					anc=anc->get_fail();
				}
				if(now!=root&&anc->get_child(i)){
					anc=anc->get_child(i);
				}
				next->set_fail(anc);
				if(next->get_fail()->get_isEnd()){
					next->set_isEnd(true);
					next->set_name(next->get_fail()->get_name());
				}
				que.push(next);
			}
		}
	}

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}