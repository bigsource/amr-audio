# amr-audio
extract amr from pacp file and write to .amr file storage format

compile environment:
linux

executable usage:  
printf("---------command for usage ---------\n");  
printf("-h (optional) get help information\n");  
printf("-i (mandatory) set input pcap file name to analyse\n");  
printf("-o (optional) set output pcap file name to analyse\n");  
printf("-w (optional) set for amr-wb codec. amr-nb codec if not set\n");  
printf("-a (optional) set for Octet-Aligned, Bandwidth-Efficient if not set\n");  
printf("-d (optional) set destination port to extract, else all port would be extracted\n");  
printf("example 1: ./extract_amr.out -i exported_tr.pcap\n");  
printf("example 2: ./extract_amr.out -i exported_tr.pcap -w -a\n");  
printf("------------------------------------\n");  

example:  
./a.out -i tcpdump.pcap -w -d 32832  
