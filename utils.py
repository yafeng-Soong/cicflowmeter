import uuid
from itertools import islice, zip_longest

import numpy


def grouper(iterable, n, max_groups=0, fillvalue=None):
    """Collect data into fixed-length chunks or blocks"""

    if max_groups > 0:
        iterable = islice(iterable, max_groups * n)

    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


def random_string():
    return uuid.uuid4().hex[:6].upper().replace("0", "X").replace("O", "Y")


def get_statistics(alist: list):
    """Get summary statistics of a list"""
    iat = dict()

    if len(alist) > 1:
        iat["total"] = sum(alist)
        iat["max"] = max(alist)
        iat["min"] = min(alist)
        float_array = numpy.array([float(x) for x in alist])
        iat["mean"] = numpy.mean(float_array)
        iat["std"] = numpy.sqrt(numpy.var(float_array))
    else:
        iat["total"] = 0
        iat["max"] = 0
        iat["min"] = 0
        iat["mean"] = 0
        iat["std"] = 0

    return iat

def csv_hearders():
    data = {
            # Basic IP information
            "src_ip": 0,
            "dst_ip": 0,
            "src_port": 0,
            "dst_port": 0,
            "protocol": 0,
            # Basic information from packet times
            "timestamp": 0,
            "flow_duration": 0,
            "flow_byts_s": 0,
            "flow_pkts_s": 0,
            "fwd_pkts_s": 0,
            "bwd_pkts_s": 0,
            # Count total packets by direction
            "tot_fwd_pkts": 0,
            "tot_bwd_pkts": 0,
            # Statistical info obtained from Packet lengths
            "totlen_fwd_pkts": 0,
            "totlen_bwd_pkts": 0,
            "fwd_pkt_len_max": 0,
            "fwd_pkt_len_min": 0,
            "fwd_pkt_len_mean": 0,
            "fwd_pkt_len_std": 0,
            "bwd_pkt_len_max": 0,
            "bwd_pkt_len_min": 0,
            "bwd_pkt_len_mean": 0,
            "bwd_pkt_len_std": 0,
            "pkt_len_max": 0,
            "pkt_len_min": 0,
            "pkt_len_mean": 0,
            "pkt_len_std": 0,
            "pkt_len_var": 0,
            "fwd_header_len": 0,
            "bwd_header_len": 0,
            "fwd_seg_size_min": 0,
            "fwd_act_data_pkts":0,
            # Flows Interarrival Time
            "flow_iat_mean":0,
            "flow_iat_max": 0,
            "flow_iat_min":0,
            "flow_iat_std":0,
            "fwd_iat_tot": 0,
            "fwd_iat_max": 0,
            "fwd_iat_min": 0,
            "fwd_iat_mean": 0,
            "fwd_iat_std": 0,
            "bwd_iat_tot":0,
            "bwd_iat_max": 0,
            "bwd_iat_min": 0,
            "bwd_iat_mean": 0,
            "bwd_iat_std": 0,
            # Flags statistics
            "fwd_psh_flags": 0,
            "bwd_psh_flags": 0,
            "fwd_urg_flags":0,
            "bwd_urg_flags": 0,
            "fin_flag_cnt": 0,
            "syn_flag_cnt": 0,
            "rst_flag_cnt": 0,
            "psh_flag_cnt": 0,
            "ack_flag_cnt": 0,
            "urg_flag_cnt": 0,
            "ece_flag_cnt": 0,
            # Response Time
            "down_up_ratio": 0,
            "pkt_size_avg":0,
            "init_fwd_win_byts": 0,
            "init_bwd_win_byts": 0,
            "active_max": 0,
            "active_min": 0,
            "active_mean": 0,
            "active_std": 0,
            "idle_max":0,
            "idle_min": 0,
            "idle_mean":0,
            "idle_std": 0,
            "fwd_byts_b_avg":0,
            "fwd_pkts_b_avg": 0,
            "bwd_byts_b_avg": 0,
            "bwd_pkts_b_avg":0,
            "fwd_blk_rate_avg": 0,
            "bwd_blk_rate_avg": 0,
    }
    # Duplicated features
    data["fwd_seg_size_avg"] = 0
    data["bwd_seg_size_avg"] = 0
    data["cwe_flag_count"] = 0
    data["subflow_fwd_pkts"] = 0
    data["subflow_bwd_pkts"] = 0
    data["subflow_fwd_byts"] = 0
    data["subflow_bwd_byts"] = 0
    return data.keys()