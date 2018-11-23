/*
     This file (was) part of GNUnet.
     Copyright (C) 2018 Christian Grothoff

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file switch.c
 * @brief Ethernet switch
 * @author Christian Grothoff
 */
#include "glab.h"
#include "print.c"


/**
 * gcc 4.x-ism to pack structures (to be used before structs);
 * Using this still causes structs to be unaligned on the stack on Sparc
 * (See #670578 from Debian).
 */
_Pragma("pack(push)") _Pragma("pack(1)")

struct EthernetHeader
{
  struct MacAddress dst;
  struct MacAddress src;
  uint16_t tag;
};

_Pragma("pack(pop)")



/**
 * Per-interface context.
 */
struct Interface
{
  /**
   * MAC of interface.
   */
  struct MacAddress mac;

  /**
   * Number of this interface.
   */
  uint16_t ifc_num;

};

struct Mapping {
    struct MacAddress mac;
    uint16_t target_ifc_num;
    time_t timeRemembered;
};



/**
 * Number of available contexts.
 */
static unsigned int num_ifc;

/**
 * All the contexts.
 */
static struct Interface *gifc;


/**
 * Forward @a frame to interface @a dst.
 *
 * @param dst target interface to send the frame out on
 * @param frame the frame to forward
 * @param frame_size number of bytes in @a frame
 */
static void
forward_to (struct Interface *dst,
	    const void *frame,
	    size_t frame_size)
{
  char iob[frame_size + sizeof (struct GLAB_MessageHeader)];
  struct GLAB_MessageHeader hdr;

  hdr.size = htons (sizeof (iob));
  hdr.type = htons (dst->ifc_num);
  memcpy (iob,
	  &hdr,
	  sizeof (hdr));
  memcpy (&iob[sizeof (hdr)],
	  frame,
	  frame_size);
  write_all (STDOUT_FILENO,
	     iob,
	     sizeof (iob));
}


/**
 * Parse and process frame received on @a ifc.
 *
 * @param ifc interface we got the frame on
 * @param frame raw frame data
 * @param frame_size number of bytes in @a frame
 */
static void
parse_frame (struct Interface *ifc,
	     const void *frame,
	     size_t frame_size)
{
  struct EthernetHeader eh;

  if (frame_size < sizeof (eh))
  {
    fprintf (stderr,
	     "Malformed frame\n");
    return;
  }
  memcpy (&eh,
	  frame,
	  sizeof (eh));
  /* do work here! */
/* TODO: save to table: sender MAC and sender Port */
    struct Mapping mapping;
    mapping.mac = eh.src;
    mapping.target_ifc_num = ifc->ifc_num;
    //mapping.timeRemembered = time(time_t *);
    /* TODO: save */
    /* TODO: get port from table for destination MAC */
    /* TODO: Forward frame to all except sender MAC */
    int a = 0;
    for (a = 0; a < num_ifc; a++) {
        if(&gifc[a].ifc_num != &ifc->ifc_num) {
            print("Frame from %u to %u forwarded\n", (unsigned)&ifc->ifc_num, (unsigned)&gifc[a].ifc_num);
            forward_to (&gifc[a], frame, frame_size);
        } else {
            print("Frame from %u to %u dropped\n", (unsigned)&ifc->ifc_num, (unsigned)&gifc[a].ifc_num);
        }
    }
}




/**
 * Process frame received from @a interface.
 *
 * @param interface number of the interface on which we received @a frame
 * @param frame the frame
 * @param frame_size number of bytes in @a frame
 */
static void
handle_frame (uint16_t interface,
	      const void *frame,
	      size_t frame_size)
{
  if (interface > num_ifc)
    abort ();
  parse_frame (&gifc[interface - 1],
	       frame,
	       frame_size);
}


/**
 * Handle control message @a cmd.
 *
 * @param cmd text the user entered
 * @param cmd_len length of @a cmd
 */
static void
handle_control (char *cmd,
		size_t cmd_len)
{
  cmd[cmd_len - 1] = '\0';
  print ("Received command `%s' (ignored)\n",
	 cmd);
}


/**
 * Handle MAC information @a mac
 *
 * @param ifc_num number of the interface with @a mac
 * @param mac the MAC address at @a ifc_num
 */
static void
handle_mac (uint16_t ifc_num,
	    const struct MacAddress *mac)
{
  if (ifc_num > num_ifc)
    abort ();
  gifc[ifc_num - 1].mac = *mac;
}


#include "loop.c"


/**
 * Launches the switch.
 *
 * @param argc number of arguments in @a argv
 * @param argv binary name, followed by list of interfaces to switch between
 * @return not really
 */
int
main (int argc,
      char **argv)
{
  struct Interface ifc[argc - 1];

  memset (ifc,
	  0,
	  sizeof (ifc));
  num_ifc = argc - 1;
  gifc = ifc;
  for (unsigned int i=1;i<argc;i++)
    ifc[i-1].ifc_num = i;

  loop ();
  return 0;
}
