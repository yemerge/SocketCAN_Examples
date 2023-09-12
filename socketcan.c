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
#define CAN0_ID              0x141
#define CAN1_ID              0x242

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
  
  frame.can_id = id & 0x1fffffff;         //\_29bit CAN ID
  frame.can_id |= CAN_EFF_FLAG;           //\_set Extended Frame Format (1 << 31)
  memcpy(frame.data, data, data_lan);
	frame.can_dlc = data_lan;
	
	if (write(s, &frame, sizeof(struct can_frame)) != sizeof(struct can_frame))
  {
		perror("Write");
		return 1;
	}

  return 0;
}

int ReceiveCanFrame(const int s)
{
  int rx_bytes;
  struct can_frame frame;
  
  rx_bytes = read(s, &frame, sizeof(struct can_frame));

  if(rx_bytes < 0)
  {
    perror("Read");
    return 1;
  }
  else if(rx_bytes < (int)sizeof(struct can_frame))
  {
    printf("Incomplete can frame is received. rx : %d bytes\n", rx_bytes);
    return 1;
  }
  else if(frame.can_dlc > CAN_FRAME_MAX_LEN)
  {
    printf("Invalid dlc : %u\n", frame.can_dlc);
    return 1;
  }

  if(frame.can_id & CAN_ERR_FLAG)
  {
    printf("Error frame is received\n");
  }
  else if(frame.can_id & CAN_RTR_FLAG)
  {
    printf("RTR frame is received\n");
  }
  else
  {
    if(frame.can_id & CAN_EFF_FLAG)
    {
      printf("29bit long ext can frame is received\n");
    }
    else
    {
      printf("11bit long std can frame is received\n");
    }
  }

  printf("0x%3X [%d] ", frame.can_id, frame.can_dlc);

  for(int i = 0; i < frame.can_dlc; i++)
  {
    printf("%02X ", frame.data[i]);
  }

  printf("\r\n");
}

int main(void)
{
  uint8_t can_data[CAN_FRAME_MAX_LEN] = {0x01, 0xa1, 0xb2, 0x03, 0x40, 0xd2, 0x8b, 0xcd};
  uint8_t can1_data[CAN_FRAME_MAX_LEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xec, 0x5a, 0xa5, 0x43};

	printf("CAN Sockets Demo\r\n");

  int s0 = InitCanInterface("can0");
  int s1 = InitCanInterface("can1");
  TransmitCanFrame(s0, CAN0_ID, can_data, sizeof(can_data));
  TransmitCanFrame(s1, CAN1_ID, can1_data, sizeof(can1_data));

  printf("CAN1 receive \r\n");
  ReceiveCanFrame(s1);
  printf("CAN0 Receive \r\n");
  ReceiveCanFrame(s0);

	return 0;
}
