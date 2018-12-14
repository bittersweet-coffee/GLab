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
#include "time.h"

/**
 * declarations
 */
static int maccmp(const struct MacAddress *mac1, const struct MacAddress *mac2);

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

struct Mapping
{
    struct MacAddress mac;
    uint16_t ifc_num;
    time_t timeRemembered;
};

static unsigned int mappings_size = 10;
static struct Mapping *mappings;
static unsigned int mappings_next_empty = 0;

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
static void forward_to(
    struct Interface *dst,
    const void *frame,
    size_t frame_size)
{
    char iob[frame_size + sizeof(struct GLAB_MessageHeader)];
    struct GLAB_MessageHeader hdr;

    hdr.size = htons(sizeof(iob));
    hdr.type = htons(dst->ifc_num);
    memcpy(iob, &hdr, sizeof(hdr));
    memcpy(&iob[sizeof(hdr)], frame, frame_size);
    write_all(STDOUT_FILENO, iob, sizeof(iob));
}

/**
 * Parse and process frame received on @a ifc.
 *
 * @param ifc interface we got the frame on
 * @param frame raw frame data
 * @param frame_size number of bytes in @a frame
 */
static void parse_frame(
    struct Interface *ifc,
    const void *frame,
    size_t frame_size)
{
    struct EthernetHeader eh;

    if (frame_size < sizeof(eh))
    {
        fprintf(stderr, "Malformed frame\n");
        return;
    }

    // Writes ethernet header from frame to eh variable.
    memcpy(&eh, frame, sizeof(eh));

    /* do work here! */

    print("SUPERSWITCH: Sender MAC [%02X:%02X:%02X:%02X:%02X:%02X] Interface [%u]\n",
    eh.src.mac[0],
    eh.src.mac[1],
    eh.src.mac[2],
    eh.src.mac[3],
    eh.src.mac[4],
    eh.src.mac[5],
    (unsigned)&ifc->ifc_num);

    if(&(eh).dst == NULL){
        print("SUPERSWITCH: Destination MAC is NULL. Is Broadcast.\n");
        int a = 0;
        for (a = 0; a < num_ifc; a++)
        {
            if (&gifc[a].ifc_num != &ifc->ifc_num)
            {
                print("Frame from %u to %u forwarded\n", (unsigned)&ifc->ifc_num, (unsigned)&gifc[a].ifc_num);
                forward_to(&gifc[a], frame, frame_size);
            }
            else
            {
                print("Frame from %u to %u dropped\n", (unsigned)&ifc->ifc_num, (unsigned)&gifc[a].ifc_num);
            }
        }
    }

    print("SUPERSWITCH: Destination MAC [%02X:%02X:%02X:%02X:%02X:%02X]\n",
    eh.dst.mac[0],
    eh.dst.mac[1],
    eh.dst.mac[2],
    eh.dst.mac[3],
    eh.dst.mac[4],
    eh.dst.mac[5]);

    // Step 1: Update info about sender Interface Number and MAC.

    time_t current = time(NULL);
    time_t oldest = time(NULL);
    int oldestIndex = 0;
    int isNew = 1;

    for (int i = 0; i < mappings_size; i++)
    {
        if(&(mappings[i]) == NULL || &(mappings[i]).mac == NULL)
        // Search for last entry for same MAC.
        if (maccmp(&(mappings[i].mac), &(eh.src)))
        {
            // Update values for this MAC.
            mappings[i].ifc_num = ifc->ifc_num;
            mappings[i].timeRemembered = current;
            // If found, is obviously no new MAC.
            isNew = 0;
            break;
        }

        // We have not found MAC entry and check if current array item is oldest.
        if (difftime(mappings[i].timeRemembered, oldest) < 0)
        {
            oldest = mappings[i].timeRemembered;
            oldestIndex = i;
        }
    }

    // If is new MAC we need to save it.
    if (isNew == 1)
    {

        int index;

        // If has free slots, save there.
        if (mappings_next_empty < mappings_size)
        {
            index = mappings_next_empty;
            mappings_next_empty++;
        }
        // Else override the oldest entry.
        else
        {
            index = oldestIndex;
        }

        mappings[index].timeRemembered = current;
        mappings[index].ifc_num = ifc->ifc_num;
        mappings[index].mac = eh.src;
    }

    // Step 2: Lookup Receiver Interface Number. If not found, broadcast.

    uint16_t destination_if;

    int found_dest_mac = 0;

    for (int i = 0; i < mappings_size; i++)
    {

        if (maccmp(&(mappings[i].mac), &(eh.dst) == 0))
        {
            destination_if = mappings[i].ifc_num;
            found_dest_mac = 1;
            break;
        }
    }

    // if we have fount the Interface for the MAC, send there
    if (found_dest_mac == 1)
    {
        forward_to(&destination_if, frame, frame_size);
    }
    // else, send to all except sender
    else
    {
        int a = 0;
        for (a = 0; a < num_ifc; a++)
        {
            if (&gifc[a].ifc_num != &ifc->ifc_num)
            {
                print("Frame from %u to %u forwarded\n", (unsigned)&ifc->ifc_num, (unsigned)&gifc[a].ifc_num);
                forward_to(&gifc[a], frame, frame_size);
            }
            else
            {
                print("Frame from %u to %u dropped\n", (unsigned)&ifc->ifc_num, (unsigned)&gifc[a].ifc_num);
            }
        }
    }
}

static char * getMacString(){

}

    /**
 * Process frame received from @a interface.
 *
 * @param interface number of the interface on which we received @a frame
 * @param frame the frame
 * @param frame_size number of bytes in @a frame
 */
    static void handle_frame(uint16_t interface,
                             const void *frame,
                             size_t frame_size)
{
    if (interface > num_ifc)
        abort();
    parse_frame(&gifc[interface - 1],
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
handle_control(char *cmd,
               size_t cmd_len)
{
    cmd[cmd_len - 1] = '\0';
    print("Received command `%s' (ignored)\n",
          cmd);
}

/**
 * Handle MAC information @a mac
 *
 * @param ifc_num number of the interface with @a mac
 * @param mac the MAC address at @a ifc_num
 */
static void
handle_mac(uint16_t ifc_num,
           const struct MacAddress *mac)
{
    if (ifc_num > num_ifc)
        abort();
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
int main(int argc,
         char **argv)
{
    struct Interface ifc[argc - 1];

    memset(ifc,
           0,
           sizeof(ifc));
    num_ifc = argc - 1;
    gifc = ifc;
    for (unsigned int i = 1; i < argc; i++)
        ifc[i - 1].ifc_num = i;

    loop();
    return 0;
}

/**
 * compare two mac addresses
 */
static int maccmp(const struct MacAddress * mac1, const struct MacAddress *mac2)
{
    return memcmp(mac1, mac2, sizeof(struct MacAddress));
}
