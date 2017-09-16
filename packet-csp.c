/* packet-csp.c
 * Routines for Cubesat Space Protocol (libcsp) dissection
 * Copyright 2017, Chris Evans <cevans3326@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * CubeSat Space Protocol (CSP) is a small network-layer delivery protocol
 * designed for CubeSats. The idea was developed by a group of students from
 * Aalborg University in 2008, and further developed for the AAUSAT3 CubeSat
 * mission that was launched in 2013. The protocol is based on a 32-bit header
 * containing both network and transport layer information. Its implementation
 * is designed for embedded systems such as the 8-bit AVR microprocessor and
 * the 32-bit ARM and AVR from Atmel. The implementation is written in C and is
 * ported to run on FreeRTOS and POSIX and pthreads-based operating systems
 * such as Linux.
 *
 * More information:
 * https://en.wikipedia.org/wiki/Cubesat_Space_Protocol
 * https://github.com/libcsp/libcsp
 */

#include <config.h>

#if 0
/* "System" includes used only as needed */
#include <stdlib.h>
#include <string.h>
...
#endif

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/decode_as.h>

// TODO: include this ??
//#include <csp/csp_types.h>
#define CSP_ID_PRIO_SIZE		2
#define CSP_ID_HOST_SIZE		5
#define CSP_ID_PORT_SIZE		6
#define CSP_ID_FLAGS_SIZE		8

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_csp(void);
void proto_register_csp(void);

/* Initialize the protocol and registered fields */
static int proto_csp    = -1;
static int hf_csp_prio  = -1;
static int hf_csp_src   = -1;
static int hf_csp_dst   = -1;
static int hf_csp_sport = -1;
static int hf_csp_dport = -1;
static int hf_csp_flags = -1;

/* Initialize the subtree pointers */
static gint ett_csp = -1;

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define CSP_MIN_LENGTH 4

/* Code to actually dissect the packets */
static int
dissect_csp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    /* Set up structures needed to add the protocol subtree and manage it */
    //proto_item *ti, *expert_ti;
    proto_tree *csp_tree;
    /* Other misc. local variables. */
    proto_item      *ti;
    guint8 bitoffs = 0;

    /*** COLUMN DATA ***/

    /* There are two normal columns to fill in: the 'Protocol' column which
     * is narrow and generally just contains the constant string 'csp',
     * and the 'Info' column which can be much wider and contain misc. summary
     * information (for example, the port number for TCP packets).
     *
     * If you are setting the column to a constant string, use "col_set_str()",
     * as it's more efficient than the other "col_set_XXX()" calls.
     *
     * If
     * - you may be appending to the column later OR
     * - you have constructed the string locally OR
     * - the string was returned from a call to val_to_str()
     * then use "col_add_str()" instead, as that takes a copy of the string.
     *
     * The function "col_add_fstr()" can be used instead of "col_add_str()"; it
     * takes "printf()"-like arguments. Don't use "col_add_fstr()" with a format
     * string of "%s" - just use "col_add_str()" or "col_set_str()", as it's
     * more efficient than "col_add_fstr()".
     *
     * For full details see section 1.4 of README.dissector.
     */

    /* Set the Protocol column to the constant string of csp */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CSP");

    /* If you will be fetching any data from the packet before filling in
     * the Info column, clear that column first in case the calls to fetch
     * data from the packet throw an exception so that the Info column doesn't
     * contain data left over from the previous dissector: */
    col_clear(pinfo->cinfo, COL_INFO);

    /*** PROTOCOL TREE ***/

    /* Now we will create a sub-tree for our protocol and start adding fields
     * to display under that sub-tree. Most of the time the only functions you
     * will need are proto_tree_add_item() and proto_item_add_subtree().
     *
     * NOTE: The offset and length values in the call to proto_tree_add_item()
     * define what data bytes to highlight in the hex display window when the
     * line in the protocol tree display corresponding to that item is selected.
     *
     * Supplying a length of -1 tells Wireshark to highlight all data from the
     * offset to the end of the packet.
     */

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_csp, tvb, 0, -1, ENC_NA);
    csp_tree = proto_item_add_subtree(ti, ett_csp);

    // Priority
    tvb_get_bits32(tvb, bitoffs, 32, CSP_ID_PRIO_SIZE);
    proto_tree_add_bits_item(csp_tree, hf_csp_prio, tvb, bitoffs, CSP_ID_PRIO_SIZE, ENC_BIG_ENDIAN);
    bitoffs += CSP_ID_PRIO_SIZE;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PRIO");
    
    // Source
    proto_tree_add_bits_item(csp_tree, hf_csp_src, tvb, bitoffs, CSP_ID_HOST_SIZE, ENC_BIG_ENDIAN);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SOURCE");
    bitoffs += CSP_ID_HOST_SIZE;

    // Dest
    proto_tree_add_bits_item(csp_tree, hf_csp_dst, tvb, bitoffs, CSP_ID_HOST_SIZE, ENC_BIG_ENDIAN);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DEST");
    bitoffs += CSP_ID_HOST_SIZE;

    // SRC PORT
    proto_tree_add_bits_item(csp_tree, hf_csp_sport, tvb, bitoffs, CSP_ID_PORT_SIZE, ENC_BIG_ENDIAN);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SPORT");
    bitoffs += CSP_ID_PORT_SIZE;

    // DST PORT
    proto_tree_add_bits_item(csp_tree, hf_csp_dport, tvb, bitoffs, CSP_ID_PORT_SIZE, ENC_BIG_ENDIAN);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPORT");
    bitoffs += CSP_ID_PORT_SIZE;

    // FLAGS
    proto_tree_add_bits_item(csp_tree, hf_csp_flags, tvb, bitoffs, CSP_ID_FLAGS_SIZE, ENC_BIG_ENDIAN);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FLAGS");
    bitoffs += CSP_ID_FLAGS_SIZE;

    /* Return the amount of data this dissector was able to dissect (which may
     * or may not be the total captured packet as we return here). */
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark.
 *
 * This format is require because a script is used to build the C function that
 * calls all the protocol registration.
 */
void
proto_register_csp(void)
{

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_csp_prio,
          { "Priority", "csp.priority",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_csp_src,
          { "Source", "csp.source",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_csp_dst,
          { "Dest", "csp.dest",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_csp_sport,
          { "Src_port", "csp.src_port",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_csp_dport,
          { "Dest_port", "csp.dest_port",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_csp_flags,
          { "Flags", "csp.flags",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_csp
    };

    /* Setup protocol expert items */
    /*
    static ei_register_info ei[] = {
        { &ei_CSP_EXPERTABBREV,
          { "CSP.EXPERTABBREV", PI_SEVERITY, PI_GROUP,
            "EXPERTDESCR", EXPFILL }
        }
    };
    */

    /* Register the protocol name and description */
    proto_csp = proto_register_protocol("Cubesat Space Protocol",
            "libcsp", "csp");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_csp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}

/* If this dissector uses sub-dissector registration add a registration routine.
 * This exact format is required because a script is used to find these
 * routines and create the code that calls these routines.
 *
 * If this function is registered as a prefs callback (see
 * prefs_register_protocol above) this function is also called by Wireshark's
 * preferences manager whenever "Apply" or "OK" are pressed. In that case, it
 * should accommodate being called more than once by use of the static
 * 'initialized' variable included below.
 *
 * This form of the reg_handoff function is used if if you perform registration
 * functions which are dependent upon prefs. See below this function for a
 * simpler form which can be used if there are no prefs-dependent registration
 * functions.
 */
#if 0
void
proto_reg_handoff_csp(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t csp_handle;
    static int current_port;

    if (!initialized) {
        /* Use create_dissector_handle() to indicate that
         * dissect_csp() returns the number of bytes it dissected (or 0
         * if it thinks the packet does not belong to PROTONAME).
         */
        csp_handle = create_dissector_handle(dissect_csp,
                proto_csp);
        initialized = TRUE;

    } else {
        /* If you perform registration functions which are dependent upon
         * prefs then you should de-register everything which was associated
         * with the previous settings and re-register using the new prefs
         * settings here. In general this means you need to keep track of
         * the csp_handle and the value the preference had at the time
         * you registered.  The csp_handle value and the value of the
         * preference can be saved using local statics in this
         * function (proto_reg_handoff).
         */
        dissector_delete_uint("tcp.port", current_port, csp_handle);
    }

    current_port = tcp_port_pref;

    dissector_add_uint("tcp.port", current_port, csp_handle);
}


#endif
/* Simpler form of proto_reg_handoff_csp which can be used if there are
 * no prefs-dependent registration function calls. */
void
proto_reg_handoff_csp(void)
{
    dissector_handle_t csp_handle;

    /* Use create_dissector_handle() to indicate that dissect_csp()
     * returns the number of bytes it dissected (or 0 if it thinks the packet
     * does not belong to PROTONAME).
     */
    csp_handle = create_dissector_handle(dissect_csp, proto_csp);
    dissector_add_for_decode_as("can.subdissector", csp_handle);

}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
