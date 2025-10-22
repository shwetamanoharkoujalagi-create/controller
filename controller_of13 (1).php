<?php

$preferred = '/var/www/html/topology.json';
if (is_writable(dirname($preferred))) {
    $TOPO_JSON = $preferred;
} else {
    $TOPO_JSON = __DIR__ . '/topology.json';
}
echo "Topology JSON path: $TOPO_JSON\n";


function save_topology_json($topology, $file) {
    $nodesSet = [];
    $edges = [];

    foreach ($topology as $key => $ts) {
        $parts = explode('->', $key);
        if (count($parts) != 2) continue;
        $left = $parts[0];
        $dstHex = $parts[1];

        $leftParts = explode(':', $left);
        if (count($leftParts) != 2) continue;
        $srcHex = $leftParts[0];
        $srcPort = $leftParts[1];

        $nodesSet[$srcHex] = true;
        $nodesSet[$dstHex] = true;

        $eid = $srcHex . '-' . $srcPort . '-' . $dstHex;

        $edges[] = [
            'id'     => $eid,
            'from'   => $srcHex,
            'to'     => $dstHex,
            'label'  => "p$srcPort",
            'arrows' => 'to'
        ];
    }

    $nodes = [];
    foreach (array_keys($nodesSet) as $hex) {
        $nodes[] = [
            'id'    => $hex,
            'label' => "DPID $hex",
            'shape' => 'box'
        ];
    }

    $payload = [
        'generated_at' => date('c'),
        'nodes' => $nodes,
        'edges' => $edges
    ];

    $json = json_encode($payload, JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES);
    $result = @file_put_contents($file, $json, LOCK_EX);

    if ($result === false) {
        echo "ERROR: Failed to write topology JSON to $file\n";
    } else {
        echo "Saved topology: nodes=" . count($nodes) . " edges=" . count($edges) . " -> $file\n";
    }
}

function prune_topology(&$topology, $ttlSeconds = 20) {
    $now = time();
    foreach ($topology as $k => $t) {
        if ($now - $t > $ttlSeconds) unset($topology[$k]);
    }
}

function build_set_config($miss_len = 0xffff, $xid = 20) {
    $OFP_VERSION = 0x04; $OFPT_SET_CONFIG = 9;
    $body = pack("nn", 0, $miss_len);
    return pack("CCnN", $OFP_VERSION, $OFPT_SET_CONFIG, 8 + strlen($body), $xid) . $body;
}

function build_flow_mod_table_miss_to_controller($priority = 0, $xid = 21) {
    $OFP_VERSION=0x04; $OFPT_FLOW_MOD=14; $OFP_NO_BUFFER=0xffffffff; $OFPP_CONTROLLER=0xfffffffd;

    $fm  = pack("NN", 0, 0) . pack("NN", 0, 0);
    $fm .= pack("C",0) . pack("C",0) . pack("n",0) . pack("n",0) . pack("n",$priority);
    $fm .= pack("N",$OFP_NO_BUFFER) . pack("N",0) . pack("N",0) . pack("n",0) . "\x00\x00";

    $match_body = "";
    $match_len_without_pad = 0;
    $match_len = $match_len_without_pad;
    $pad = (8 - ($match_len % 8)) % 8;
    $match = pack("nn", 1, $match_len + $pad) . $match_body . str_repeat("\x00", $pad);

    $action = pack("nnNn", 0, 16, $OFPP_CONTROLLER, 0xffff) . str_repeat("\x00", 6);
    $inst   = pack("nn", 4, 8 + strlen($action)) . $action;

    $payload = $fm . $match . $inst;
    return pack("CCnN", $OFP_VERSION, $OFPT_FLOW_MOD, 8 + strlen($payload), $xid) . $payload;
}

function build_flow_mod_eth_type_to_controller($eth_type = 0x88cc, $priority = 1000, $xid = 22) {
    $OFP_VERSION=0x04; $OFPT_FLOW_MOD=14; $OFP_NO_BUFFER=0xffffffff; $OFPP_CONTROLLER=0xfffffffd;

    $fm  = pack("NN", 0, 0) . pack("NN", 0, 0);
    $fm .= pack("C",0) . pack("C",0) . pack("n",0) . pack("n",0) . pack("n",$priority);
    $fm .= pack("N",$OFP_NO_BUFFER) . pack("N",0) . pack("N",0) . pack("n",0) . "\x00\x00";

    $oxm_header = pack("nC C", 0x8000, (5<<1)|0, 2);
    $oxm_value  = pack("n", $eth_type);
    $oxm = $oxm_header . $oxm_value;

    $match_len_without_pad = strlen($oxm);
    $pad = (8 - (($match_len_without_pad + 0) % 8)) % 8;
    $match = pack("nn", 1, $match_len_without_pad + $pad) . $oxm . str_repeat("\x00", $pad);

    $action = pack("nnNn", 0, 16, $OFPP_CONTROLLER, 0xffff) . str_repeat("\x00",6);
    $inst   = pack("nn", 4, 8+strlen($action)) . $action;

    $payload = $fm . $match . $inst;
    return pack("CCnN", $OFP_VERSION, $OFPT_FLOW_MOD, 8+strlen($payload), $xid) . $payload;
}


$OFP_VERSION              = 0x04;
$OFPT_HELLO               = 0;
$OFPT_ERROR               = 1;
$OFPT_ECHO_REQUEST        = 2;
$OFPT_ECHO_REPLY          = 3;
$OFPT_FEATURES_REQUEST    = 5;
$OFPT_FEATURES_REPLY      = 6;
$OFPT_PACKET_IN           = 10;
$OFPT_FLOW_MOD            = 14;
$OFPT_PACKET_OUT          = 13;
$OFPT_MULTIPART_REQUEST   = 18;
$OFPT_MULTIPART_REPLY     = 19;

$OFPMP_PORT_DESC          = 13;

$OFPP_MAX                 = 0xffffff00;
$OFPP_CONTROLLER          = 0xfffffffd;
$OFP_NO_BUFFER            = 0xffffffff;

$lldp_multicast           = "\x01\x80\xc2\x00\x00\x0e";
$ethertype_lldp           = "\x88\xcc";

$switches = [];
$clients  = [];
$topology = [];

function be64_to_str($x) {
    $hi = ($x >> 32) & 0xffffffff;
    $lo = $x & 0xffffffff;
    return pack("NN", $hi, $lo);
}
function str_to_be64($s8) {
    $a = unpack("Nhi/Nlo", $s8);
    return ($a['hi'] << 32) | $a['lo'];
}
function build_of_header($msg_type, $length, $xid = 1) {
    global $OFP_VERSION;
    return pack("CCnN", $OFP_VERSION, $msg_type, $length, $xid);
}
function build_hello($xid = 1) {
    return build_of_header(0, 8, $xid); // OFPT_HELLO
}
function build_features_request($xid = 1) {
    global $OFPT_FEATURES_REQUEST;
    return build_of_header($OFPT_FEATURES_REQUEST, 8, $xid);
}
function build_multipart_port_desc_request($xid = 2) {
    global $OFPT_MULTIPART_REQUEST, $OFPMP_PORT_DESC;
    $len = 8 + 8;
    $msg  = build_of_header($OFPT_MULTIPART_REQUEST, $len, $xid);
    $msg .= pack("nnN", $OFPMP_PORT_DESC, 0, 0);
    return $msg;
}
function build_lldp_packet($dpid, $port_no) {
    global $lldp_multicast, $ethertype_lldp;
    $dpid8 = be64_to_str($dpid);
    $chassis_mac = substr($dpid8, 2, 6);

    $chassis_subtype = chr(4);
    $chassis_val = $chassis_subtype . $chassis_mac;
    $chassis_hdr = pack("n", (1 << 9) | strlen($chassis_val));
    $chassis_tlv = $chassis_hdr . $chassis_val;

    $port_subtype = chr(3);
    $port_val = $port_subtype . pack("n", $port_no);
    $port_hdr = pack("n", (2 << 9) | strlen($port_val));
    $port_tlv = $port_hdr . $port_val;

    $ttl_val = pack("n", 120);
    $ttl_hdr = pack("n", (3 << 9) | 2);
    $ttl_tlv = $ttl_hdr . $ttl_val;

    $end_tlv = pack("n", 0);

    $lldp_payload = $chassis_tlv . $port_tlv . $ttl_tlv . $end_tlv;

    $eth = $lldp_multicast . $chassis_mac . $ethertype_lldp . $lldp_payload;
    return $eth;
}
function build_packet_out_of13($port_no, $data, $xid = 3) {

    global $OFPT_PACKET_OUT, $OFP_NO_BUFFER, $OFPP_CONTROLLER;

    $action = pack("nnNn", 0, 16, $port_no, 0) . str_repeat("\x00", 6);
    $actions_len = strlen($action);

    $header_and_po = build_of_header($OFPT_PACKET_OUT, 0, $xid);
    $body  = pack("NNn", $OFP_NO_BUFFER, $OFPP_CONTROLLER, $actions_len) . str_repeat("\x00", 6);
    $msg   = $header_and_po . $body . $action . $data;

    $len = strlen($msg);
    $msg = substr($msg, 0, 2) . pack("n", $len) . substr($msg, 4);
    return $msg;
}
function parse_features_reply_of13($payload) {
    if (strlen($payload) < 24) return [null];
    $dpid = str_to_be64(substr($payload, 0, 8));
    return [$dpid];
}
function parse_multipart_port_desc_reply($payload) {
    if (strlen($payload) < 8) return [];
    $ports = [];
    $off = 8;
    while ($off + 64 <= strlen($payload)) {
        $port_raw = substr($payload, $off, 4);
        $u = unpack("Nport", $port_raw);
        $port_no = $u['port'];
        if ($port_no < 0xffffff00) {
            $ports[] = $port_no;
        }
        $off += 64;
    }
    return $ports;
}
function parse_lldp_tlvs($lldp_payload)
{
    $src_dpid = null;
    $src_port = null;
    $offset = 0;
    $len = strlen($lldp_payload);

    while ($offset + 2 <= $len) {
        $tlv_header = unpack("n", substr($lldp_payload, $offset, 2))[1];
        $type = ($tlv_header >> 9) & 0x7F;
        $tlv_len = $tlv_header & 0x1FF;
        $offset += 2;

        if ($offset + $tlv_len > $len) break;
        $value = substr($lldp_payload, $offset, $tlv_len);
        $offset += $tlv_len;

        printf("TLV type=%d len=%d hex=%s\n", $type, $tlv_len, bin2hex($value));

        if ($type == 1 && $tlv_len >= 7) {
            $subtype = ord($value[0]);
            if ($subtype == 4) {
                $mac_bytes = substr($value, 1, 6);
                $src_dpid = strtoupper(bin2hex($mac_bytes));
                echo "Parsed DPID raw hex: $src_dpid\n";
            }
        } elseif ($type == 2 && $tlv_len >= 2) {
            $subtype = ord($value[0]);
            $src_port = ord($value[$tlv_len - 1]);
            echo "Parsed Port ID: $src_port\n";
        } elseif ($type == 0) {
            break;
        }
    }

    if ($src_dpid !== null) {
        $src_dpid_int = hexdec(substr($src_dpid, -4));
    } else {
        $src_dpid_int = null;
    }

    return [$src_dpid_int, $src_port];
}

function parse_packet_in_v13_extract_eth($payload)
{
    if (strlen($payload) < 24) return null;

    $offset = 16;

    if (strlen($payload) < $offset + 4) return null;
    $match_type = unpack("n", substr($payload, $offset, 2))[1];
    $match_len  = unpack("n", substr($payload, $offset + 2, 2))[1];
    $offset += $match_len;

    if ($offset % 8 !== 0) {
        $offset += 8 - ($offset % 8);
    }

    $offset += 2;

    if ($offset >= strlen($payload)) return null;
    return substr($payload, $offset);
}

function read_exact($s, $n) {
    $buf = "";
    while (strlen($buf) < $n) {
        $chunk = fread($s, $n - strlen($buf));
        if ($chunk === false || $chunk === "") return false;
        $buf .= $chunk;
    }
    return $buf;
}
function socket_id($s) { return (int)$s; }

$server = stream_socket_server("tcp://0.0.0.0:6653", $errno, $errstr);
if (!$server) { echo "Server error: $errstr ($errno)\n"; exit(1); }
stream_set_blocking($server, false);
echo "OF1.3 LLDP Controller listening on 6653\n";

$last_tick = microtime(true);

while (true) {
    $read = [$server];
    foreach ($clients as $c) $read[] = $c['sock'];
    $write = null; $except = null;
    $n = stream_select($read, $write, $except, 0, 500000);
    if ($n === false) { echo "select() error\n"; break; }

    // Accept new
    if (in_array($server, $read, true)) {
        $conn = @stream_socket_accept($server, 0);
        if ($conn) {
            stream_set_blocking($conn, false);
            $id = socket_id($conn);
            $clients[$id] = ['sock'=>$conn, 'phase'=>'hello', 'dpid'=>null];
            fwrite($conn, build_hello(1));
            echo "New TCP, sent HELLO\n";
        }
        $read = array_filter($read, fn($s) => $s !== $server);
    }

    foreach ($read as $sock) {
        $id = socket_id($sock);
        if (!isset($clients[$id])) { fclose($sock); continue; }

        $hdr = read_exact($sock, 8);
        if ($hdr === false) {
            $dpid = $clients[$id]['dpid'];
            if ($dpid !== null) { echo "Switch " . dechex($dpid) . " disconnected\n"; unset($switches[$dpid]); }
            else { echo "Client disconnected\n"; }
            fclose($sock); unset($clients[$id]); continue;
        }
        $h = unpack("Cver/Ctype/nlen/Nxid", $hdr);
        $type = $h['type']; $len = $h['len']; $xid = $h['xid'];
        $payload_len = max(0, $len - 8);
        $payload = $payload_len ? read_exact($sock, $payload_len) : "";

        if ($type == $OFPT_ECHO_REQUEST) {
            $reply = build_of_header($OFPT_ECHO_REPLY, 8 + strlen($payload), $xid) . $payload;
            fwrite($sock, $reply);
            echo "Echo replied\n";
            continue;
        } elseif ($type == $OFPT_ERROR) {
            if (strlen($payload) >= 4) {
                $err = unpack("netype/necode", substr($payload, 0, 4));
                $et = $err['etype']; $ec = $err['ecode'];
                echo "OF ERROR (len=$len) => err_type=$et err_code=$ec\n";
            } else {
                echo "OF ERROR (len=$len) => payload too short to parse\n";
            }
            $hex = substr(bin2hex($payload), 0, 96);
            echo "OF ERROR payload hex head: $hex\n";
            continue;
        }

        if ($clients[$id]['phase'] === 'hello') {
            if ($type != $OFPT_HELLO) { echo "Expected HELLO, got type $type\n"; }
            fwrite($sock, build_features_request(10));
            $clients[$id]['phase'] = 'wait_features';
            echo "Sent FEATURES_REQUEST\n";
            continue;
        }

        if ($clients[$id]['phase'] === 'wait_features') {
            if ($type != $OFPT_FEATURES_REPLY) {
                echo "Expected FEATURES_REPLY, got type $type\n";
                continue;
            }
            [$dpid] = parse_features_reply_of13($payload);
            if ($dpid === null) { echo "Bad FEATURES_REPLY\n"; continue; }
            $clients[$id]['dpid'] = $dpid;
            $clients[$id]['phase'] = 'ready';
            $switches[$dpid] = ['sock'=>$sock, 'ports'=>[], 'last_lldp'=>0];
            echo "Switch connected: DPID=" . dechex($dpid) . "\n";

            fwrite($sock, build_multipart_port_desc_request(11));
            echo "Sent PORT_DESC request\n";

            fwrite($sock, build_set_config(0xffff));                        echo "Sent SET_CONFIG\n";
            continue;
        }

        if ($clients[$id]['phase'] === 'ready') {
            if ($type == $OFPT_MULTIPART_REPLY) {
                $ports = parse_multipart_port_desc_reply($payload);
                if (!empty($ports)) {
                    $dpid = $clients[$id]['dpid'];
                    $switches[$dpid]['ports'] = $ports;
                    echo "Ports for " . dechex($dpid) . ": [" . implode(",", $ports) . "]\n";
                } else {
                    echo "Received PORT_DESC but no usable ports for " . dechex($clients[$id]['dpid']) . "\n";
                }
            } elseif ($type == $OFPT_PACKET_IN) {

                echo "---- PACKET_IN ----\n";
                echo "DEBUG: PACKET_IN payload len=" . strlen($payload) . "\n";

                $eth = parse_packet_in_v13_extract_eth($payload);

                if ($eth === null) {
                    echo "DEBUG: parse_packet_in_v13_extract_eth() returned NULL\n";
                } else {
                    $eth_len = strlen($eth);
                    echo "DEBUG: Ethernet frame length=$eth_len\n";

                    if ($eth_len >= 14) {
                        $ethertype_hex = bin2hex(substr($eth, 12, 2));
                        echo "DEBUG: Ethertype=$ethertype_hex (should be 88cc for LLDP)\n";

                        if ($ethertype_hex === "88cc") {
                            $lldp_payload = substr($eth, 14);
                            echo "LLDP packet detected, payload len=" . strlen($lldp_payload) . "\n";

                            [$src_dpid, $src_port] = parse_lldp_tlvs($lldp_payload);

                            if ($src_dpid !== null && $src_port !== null) {
                                $dst_dpid = $clients[$id]['dpid'];
                                $key = dechex($src_dpid) . ":" . $src_port . "->" . dechex($dst_dpid);

                                if (!isset($topology[$key])) {
                                    $topology[$key] = time();
                                    echo "Discovered link: " . dechex($src_dpid) . ":" . $src_port . " --> " . dechex($dst_dpid) . "\n";
                                    prune_topology($topology, 20);
                                    save_topology_json($topology, $TOPO_JSON);
                                }
                            } else {
                                echo "LLDP parse failed (src_dpid or src_port null)\n";
                            }
                        }
                    } else {
                        echo "DEBUG: Ethernet frame too short ($eth_len bytes)\n";
                    }
                }
            }
        }
    }

    $now = microtime(true);
    if ($now - $last_tick >= 0.25) {
        foreach ($switches as $dpid => &$sw) {
            if (empty($sw['ports'])) continue;
            if ($now - $sw['last_lldp'] >= 5.0) {
                foreach ($sw['ports'] as $p) {
                    if ($p <= 0 || $p >= 0xffffff00) continue;
                    $pkt = build_lldp_packet($dpid, $p);
                    $msg = build_packet_out_of13($p, $pkt, 100);
                    fwrite($sw['sock'], $msg);
                }
                $sw['last_lldp'] = $now;
                echo "Sent LLDP on " . dechex($dpid) . " ports [" . implode(",", $sw['ports']) . "]\n";
            }
        }
        prune_topology($topology, 20);
        save_topology_json($topology, $TOPO_JSON);
        unset($sw);
        $last_tick = $now;
    }
}


