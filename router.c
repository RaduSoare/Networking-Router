#include "skel.h"
#include<stdlib.h>
#include<stdio.h>
#include<net/if_arp.h>
#include<netinet/if_ether.h>
#include<asm/byteorder.h>
#include<queue.h>
#include<string.h>

#define BUFFER_LENGTH 255
#define RTABLE_SIZE 65000
#define ARP_TYPE 1544
#define IP_TYPE 8
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define MAC_ADRESS_LEN 6
#define IP_ADRESS_LEN 4

typedef struct rtable_entry {
	uint32_t prefix;
	uint32_t next_hop;
	char* mask;
	int interface;
}RTableEntry;

typedef struct{
	uint8_t ip[IP_ADRESS_LEN];
	uint8_t mac[MAC_ADRESS_LEN];
}ArpTableEntry;


/*
 Functia de checksum folosita la laborator
*/
uint16_t ip_checksum(void* vdata,size_t length) {
	// Cast the data pointer to one that can be indexed.
	char* data=(char*)vdata;

	// Initialise the accumulator.
	uint64_t acc=0xffff;

	// Handle any partial block at the start of the data.
	unsigned int offset=((uintptr_t)data)&3;
	if (offset) {
		size_t count=4-offset;
		if (count>length) count=length;
		uint32_t word=0;
		memcpy(offset+(char*)&word,data,count);
		acc+=ntohl(word);
		data+=count;
		length-=count;
	}

	// Handle any complete 32-bit blocks.
	char* data_end=data+(length&~3);
	while (data!=data_end) {
		uint32_t word;
		memcpy(&word,data,4);
		acc+=ntohl(word);
		data+=4;
	}
	length&=3;

	// Handle any partial block at the end of the data.
	if (length) {
		uint32_t word=0;
		memcpy(&word,data,length);
		acc+=ntohl(word);
	}

	// Handle deferred carries.
	acc=(acc&0xffffffff)+(acc>>32);
	while (acc>>16) {
		acc=(acc&0xffff)+(acc>>16);
	}

	// If the data began at an odd byte address
	// then reverse the byte order to compensate.
	if (offset&1) {
		acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
	}

	// Return the checksum in network byte order.
	return htons(~acc);
}

/*
* Cautare binara modificata pentru gasirea celei mai bune rute
* spre adresa ip primita ca parametru
*/
RTableEntry* get_best_route_from_rtable(RTableEntry* rtable, int rtable_size,
 __u32 destination_ip) {
	int left = 0, right = rtable_size - 1;
	while (right >= left) {
		int mid = left + (right - left) / 2;
		uint32_t ip_searched = (destination_ip & inet_addr(rtable[mid].mask));
		if(rtable[mid].prefix < ip_searched)
			left = mid + 1;
		else if (rtable[mid].prefix > ip_searched)
			right = mid - 1;
		else if(left != mid)
			right = mid;
		else
		 	return &rtable[mid];

	}
	return NULL;

}
/*
* Functie de comparare pentru qsort
* compara intai dupa prefix, apoi dupa masca
*/
int ip_comparator(const void* a, const void* b) {
	const RTableEntry* x = a;
	const RTableEntry* y = b;

	if(x->prefix == y->prefix)
		return strcmp(y->mask, x->mask);

	return x->prefix - y->prefix;
}

/*
* Functie pentru parsarea tabelei de routare
* care apoi este sortata cu ajutorul QuickSort
*/
int read_rtable(RTableEntry* rtable) {

	char delimiter[] = " ";
	FILE* fp = fopen("rtable.txt", "r");
	if (fp == NULL) {
		printf("File cannot be opened!\n");
	}
	char rtable_line[BUFFER_LENGTH];
	int rtable_size = 0;
	while (fgets(rtable_line, BUFFER_LENGTH, fp)) {
		char* word;
		word = strtok(rtable_line, delimiter);
		int column = 1;
		while (word != NULL) {
			if (column == 1)
				rtable[rtable_size].prefix = inet_addr(word);
			else if (column == 2)
				rtable[rtable_size].next_hop = inet_addr(word);
			else if (column == 3) {
				rtable[rtable_size].mask = malloc(30 * sizeof(char));
				strcpy(rtable[rtable_size].mask,word);
			}
			else if (column == 4) {
				rtable[rtable_size].interface = atoi(word);
			}
			column++;
			if (column == 5) {
				column = 1;
			}
			word = strtok(NULL, delimiter);
		}
		rtable_size++;
	}
	qsort(rtable, rtable_size, sizeof(RTableEntry), ip_comparator);

	return rtable_size;
}

/*
* Cautarea unei adrese IP in tabela ARP
*/
ArpTableEntry* get_arp_entry (ArpTableEntry* arp_table, int arp_table_len,
	uint8_t* ip) {
	if(arp_table_len == 0) {
		return NULL;
	}
	for(int i = 0; i < arp_table_len; i++) {
		int matched_fields = 0;
		for(int j = 0; j < IP_ADRESS_LEN; j++) {
			if(arp_table[i].ip[j] == ip[j])
				matched_fields++;
		}
		if(matched_fields == IP_ADRESS_LEN) {
			return &arp_table[i];
		}
	}
	return NULL;
}

/*
* Conversia unei adrese IP din forma decimala in forma human-readable
*/
u_char* decimal_to_uchar_ip(uint32_t ip, int size) {
	u_char* ip_arr = malloc(size * sizeof(u_char));
	struct in_addr aux;
	aux.s_addr = ip;
	char* ip_string = inet_ntoa(aux);
	int i = 0;
	char* buf;
	buf = strtok(ip_string, ".");
	while (buf != NULL) {
		ip_arr[i] = atoi(buf);
		i++;
		buf = strtok(NULL, ".");
	}
	return ip_arr;
}

/*
* Modifica campurile dintr-un header ethernet
*/
void modify_ether_header(struct ether_header *eth_hdr, uint8_t* mac_source,
	uint8_t* mac_dest) {
        for(int i = 0; i < MAC_ADRESS_LEN; i++) {
					eth_hdr->ether_shost[i] = mac_source[i];
					eth_hdr->ether_dhost[i] = mac_dest[i];
				}
        eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);
}

/*
* Modifica campurile dintr-un header arp
*/
void modify_arp_header(struct ether_arp *arp_operation, uint8_t* mac_source,
	uint8_t* mac_dest, uint8_t* ip_source, uint8_t* ip_dest, int arp_type) {

  for(int i = 0; i < MAC_ADRESS_LEN; i++) {
     arp_operation->arp_sha[i] = mac_source[i];
     arp_operation->arp_tha[i] = mac_dest[i];
   }
   for(int i = 0; i < IP_ADRESS_LEN; i++) {
     arp_operation->arp_spa[i] = ip_source[i];
     arp_operation->arp_tpa[i] = ip_dest[i];
   }
   arp_operation->ea_hdr.ar_hrd = ntohs(0x0001);
   arp_operation->ea_hdr.ar_pro = ntohs(0x0800);
   arp_operation->ea_hdr.ar_hln = MAC_ADRESS_LEN;
   arp_operation->ea_hdr.ar_pln = IP_ADRESS_LEN;
   arp_operation->ea_hdr.ar_op = ntohs(arp_type);
}

/*
* Asignare de adrese
*/
void copy_adress(int size, uint8_t* adress_source, uint8_t* adress_dest) {
	for(int i = 0; i < size; i++) {
		adress_source[i] = adress_dest[i];
	}
}

/*
* Generare de adrese mac pline cu o anumita valoare
*/
uint8_t* mac_generator(int value) {
	uint8_t* mac = malloc(MAC_ADRESS_LEN * sizeof(uint8_t));
	for(int i = 0; i < MAC_ADRESS_LEN; i++) {
		mac[i] = value;
	}
	return mac;
}

/*
* Interschimbare de adrese
*/
void swap_adress(int size, uint8_t* adr1, uint8_t* adr2) {
	uint8_t* aux = malloc(size * sizeof(uint8_t));
	for(int i = 0; i < size; i++) {
		aux[i] = adr1[i];
		adr1[i] = adr2[i];
		adr2[i] = aux[i];
	}

}
/*
* Interschimbare de adrese IP in format decimal
*/
void swap_ip_adress(uint32_t *ip1, uint32_t *ip2) {
	uint32_t aux = 0;
	aux = *ip1;
	*ip1 = *ip2;
	*ip2 = aux;

}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init();

	RTableEntry* rtable = (RTableEntry*)malloc(RTABLE_SIZE * sizeof(RTableEntry));
	// citire + sortare tabela de routare
	int rtable_size = read_rtable(rtable);
	// initializare array tabela arp
	ArpTableEntry* arp_table = malloc(4 * sizeof(ArpTableEntry));
	int arp_table_len = 0;

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		// extragere header ethernet
		struct ether_header *eth_hdr = (struct ether_header *)(m.payload);

		// verificare daca pachetul e de tip ip
		if(eth_hdr->ether_type == IP_TYPE) {
			// extragere header ip
			struct iphdr* ip_hdr = (struct iphdr *)(m.payload +
				sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));
			if(ip_hdr->daddr == inet_addr(get_interface_ip(m.interface))) {
				// raspuns icmp reply
				ip_hdr->protocol = 1;
				icmp_hdr->type = 0;
				icmp_hdr->code = 0;
				icmp_hdr->checksum = 0;
				icmp_hdr->checksum =  ip_checksum(ip_hdr, sizeof(struct iphdr) + sizeof(struct icmphdr));

				swap_adress(MAC_ADRESS_LEN, eth_hdr->ether_dhost, eth_hdr->ether_shost);
				swap_ip_adress(&ip_hdr->saddr, &ip_hdr->daddr);

				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
				m.len =  sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
				send_packet(m.interface, &m);
				continue;
			}
			// verificare checksum
			__u16 ck = ip_hdr->check;
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
			if(ip_hdr->check != ck) {
				continue;
			}
			// verificare + decrementare TTL
			if(ip_hdr->ttl < 1) {
				continue;
			}
			ip_hdr->ttl--;
			if(ip_hdr->ttl <= 0) {
					// raspuns icmp timeout
					ip_hdr->protocol = 1;
					icmp_hdr->type = 11;
	 				icmp_hdr->code = 0;
	 				icmp_hdr->checksum = 0;
	 				icmp_hdr->checksum =  ip_checksum(ip_hdr, sizeof(struct iphdr) + sizeof(struct icmphdr));

	 				swap_adress(MAC_ADRESS_LEN, eth_hdr->ether_dhost, eth_hdr->ether_shost);
	 				swap_ip_adress(&ip_hdr->saddr, &ip_hdr->daddr);

	 				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	 				m.len =  sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	 				send_packet(m.interface, &m);
					continue;
			}

			// recalculare checksum
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

			// cautare in tabela de routare a celei mai bune rute spre destinatie
			struct rtable_entry* best_route = get_best_route_from_rtable(rtable,
				rtable_size,ip_hdr->daddr);
			// daca nu s-a gasit o ruta pana la destinatie se da drop la pachet
			if(best_route == NULL) {
					// raspuns icmp host unreachable
					ip_hdr->protocol = 1;
					icmp_hdr->type = 3;
	 				icmp_hdr->code = 0;
	 				icmp_hdr->checksum = 0;
	 				icmp_hdr->checksum =  ip_checksum(ip_hdr, sizeof(struct iphdr) + sizeof(struct icmphdr));

	 				swap_adress(MAC_ADRESS_LEN, eth_hdr->ether_dhost, eth_hdr->ether_shost);
	 				swap_ip_adress(&ip_hdr->saddr, &ip_hdr->daddr);

	 				ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	 				m.len =  sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	 				send_packet(m.interface, &m);
					continue;
			}

			// extragere mac router
			uint8_t* mac_router = malloc(MAC_ADRESS_LEN * sizeof(uint8_t));
			get_interface_mac(best_route->interface, mac_router);
			// se verifica daca exista o intrare in tabela ARP pentru next_hop
			if(get_arp_entry(arp_table, arp_table_len,
				decimal_to_uchar_ip(best_route->next_hop, IP_ADRESS_LEN)) == NULL) {

				// conversii pentru usurarea prelucrarii adreselor
				u_char* next_hop = decimal_to_uchar_ip(best_route->next_hop,
					IP_ADRESS_LEN);
				u_char* router_ip = decimal_to_uchar_ip(
					inet_addr(get_interface_ip(best_route->interface)), IP_ADRESS_LEN);

				// generare adresa mac pt broadcast si arp-request
				uint8_t* broadcast_mac = mac_generator(255);
				uint8_t* empty_mac = mac_generator(0);

				// extragere header arp
				struct ether_arp* arp_request = (struct ether_arp *)(m.payload +
					sizeof(struct ether_header));
				// modificare header arp si ethernet pentru trimitere request
				modify_ether_header(eth_hdr, mac_router, broadcast_mac);
				modify_arp_header(arp_request, mac_router, empty_mac, router_ip,
					next_hop, ARP_REQUEST);

				// recalculare lungime pachet
				m.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
				send_packet(best_route->interface, &m);

			} else {
				// tratare caz in care ip-ul destinatie are o intrare in tabela ARP
				ArpTableEntry* best_arp_entry = get_arp_entry(arp_table, arp_table_len,
					decimal_to_uchar_ip(best_route->next_hop, IP_ADRESS_LEN));

				// modificare adresa mac sursa in adresa routerului
				copy_adress(MAC_ADRESS_LEN, eth_hdr->ether_shost, mac_router);

				// modificare adresa mac destinatie in adresa primita prin arp-reply
				copy_adress(MAC_ADRESS_LEN, eth_hdr->ether_dhost, best_arp_entry->mac);

				send_packet(best_route->interface, &m);
			}
	} else
		// verificare daca pachetul este de tip ARP
		if(eth_hdr->ether_type == ARP_TYPE) {
			// extragere header arp
			 struct ether_arp* arp_request = (struct ether_arp *)(m.payload +
				 sizeof(struct ether_header));

			 // tratare caz arp request
			 if(htons(arp_request->ea_hdr.ar_op) == ARP_REQUEST) {

				 uint8_t* mac_router = malloc(MAC_ADRESS_LEN * sizeof(uint8_t));
				 get_interface_mac(m.interface, mac_router);

				 /*
				 prelucrare headere de arp si ethernet pentru a trimite
				 reply cu adresa mac a routerului
				 */
				 copy_adress(MAC_ADRESS_LEN, arp_request->arp_tha, arp_request->arp_sha);
				 copy_adress(MAC_ADRESS_LEN, arp_request->arp_sha, mac_router);
				 copy_adress(MAC_ADRESS_LEN, eth_hdr->ether_dhost, eth_hdr->ether_shost);
				 copy_adress(MAC_ADRESS_LEN, eth_hdr->ether_shost, mac_router);
				 swap_adress(IP_ADRESS_LEN, arp_request->arp_spa, arp_request->arp_tpa);

				 eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);
				 arp_request->ea_hdr.ar_hrd = ntohs(0x0001);
				 arp_request->ea_hdr.ar_pro = ntohs(0x0800);
				 arp_request->ea_hdr.ar_hln = MAC_ADRESS_LEN;
				 arp_request->ea_hdr.ar_pln = IP_ADRESS_LEN;
				 arp_request->ea_hdr.ar_op = ntohs(ARP_REPLY);

				 m.len = sizeof(struct ether_header) + sizeof(struct ether_arp);
				 send_packet(m.interface, &m);
			 } else
			 // tratare caz arp_reply
			 if(htons(arp_request->ea_hdr.ar_op) == ARP_REPLY) {

				 /*
				 daca se primeste arp_reply se actualizeaza headerul de ethernet
				 si se adauga o intrare noua in tabela ARP
				 */
				 copy_adress(MAC_ADRESS_LEN, arp_table[arp_table_len].mac, arp_request->arp_sha);
				 copy_adress(MAC_ADRESS_LEN, eth_hdr->ether_dhost, arp_request->arp_sha);
				 copy_adress(IP_ADRESS_LEN, arp_table[arp_table_len].ip,  arp_request->arp_spa);
				 arp_table_len++;
			 }

		}

	}
}
