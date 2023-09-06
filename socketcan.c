#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#define CAN_FRAME_MAX_LEN   8
#define CAN_ID              0x141

int InitCanInterface(const char *ifname)
{
  // create a socket
  int s;
  if ((s = socket(PF_CAN, SOCK_RAW, CAN_RAW)) < 0)
  {
		perror("Socket");
		return 1;
	}
  
  // retrieve the interface index for the interface name
  struct ifreq ifr;
  strcpy(ifr.ifr_name, ifname);
	ioctl(s, SIOCGIFINDEX, &ifr);

  // bind the socket
	struct sockaddr_can addr;
  memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_CAN;
	addr.can_ifindex = ifr.ifr_ifindex;

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("Bind");
		return 1;
	}
  
  return s;
}

int TransmitCanFrame(const int s, const uint32_t id, const uint8_t *data, const size_t data_lan)
{
  struct can_frame frame;
  
  frame.can_id = id & 0x1fffffff;
  frame.can_id |= (1 << 31);
  memcpy(frame.data, data, data_lan);
	frame.can_dlc = data_lan;
	
	if (write(s, &frame, sizeof(struct can_frame)) != sizeof(struct can_frame))
  {
		perror("Write");
		return 1;
	}

  return 0;
}

int main(void)
{
  uint8_t can_data[CAN_FRAME_MAX_LEN] = {0x01, 0xa1, 0xb2, 0x03, 0x40, 0xd2, 0x8b, 0xcd};

	printf("CAN Sockets Demo\r\n");

  int s = InitCanInterface("can0");
  TransmitCanFrame(s, CAN_ID, can_data, sizeof(can_data));

	return 0;
}