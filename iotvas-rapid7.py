import sys
import os
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime


import iotvas
import rapid7vmconsole
from iotvas.apis import DeviceApi, FirmwareApi
from config import app_config
from utils import logging, get_logger, get_iotvas_client, get_vmconsole_client

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

logger = get_logger(__name__, logging.INFO, app_config['log_dir'])


iotvas_client = get_iotvas_client()
device_api = DeviceApi(iotvas_client)
firmware_api = FirmwareApi(iotvas_client)

vmconsole_client = get_vmconsole_client()
tag_api = rapid7vmconsole.TagApi(vmconsole_client)
asset_api = rapid7vmconsole.AssetApi(vmconsole_client)


# dict of name:id to cache insightvm tag_name:tag_id
custom_tags = {}


def get_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--targets-file", action="store", dest="targets_file", \
        help="path to the target list file", metavar="TARGETS_LIST_FILE")
    parser.add_argument("-e", "--exclude-targets", action="store", dest="excludes", \
        help="path to the nmap excluded targets file", metavar="NMAP_EXCLUDES_FILE")

    return parser


def get_tag_id(name):
    try:
        _id = None
        res = tag_api.get_tags(name=name)
        for tag in res.resources:
            if tag.name == name:
                _id = tag.id
                logger.info("Id of tag {0} is {1}".format(name, _id))
                break
        return _id
    except rapid7vmconsole.rest.ApiException:
        logger.error("Error getting tag id of {0}".format(name), exc_info=True)


def get_custom_tag(name, asset_id):
    if name in custom_tags.keys():
        return custom_tags[name]
    # otherwise, ask insightvm
    tag_id = get_tag_id(name)
    if tag_id:
        # cache this id
        custom_tags[name] = tag_id
    return tag_id


def find_asset(ip):
    try:
        res = asset_api.find_assets({"match":"all", "filters": \
            [{"field":"ip-address", "operator": "is", "value": ip}]})
        if len(res.resources) == 1:
            return res.resources[0]
    except rapid7vmconsole.rest.ApiException:
        logger.error("Failed to search asset with ip {0}".format(ip), exc_info=True)


def get_asset_tags(_id):
    tags = {}
    try:
        res = asset_api.get_asset_tags(_id)
        if len(res.resources) > 0:
            for tag in res.resources:
                if tag.type == "custom":
                    tags[tag.name] = tag.id
    except rapid7vmconsole.rest.ApiException:
        logger.error("Failed to get asset tags for id {0}".format(_id), exc_info=True)
    return tags

def tag_asset(asset_id, tag_id, tag_name):
    if not tag_id:
        return
    try:
        asset_api.add_asset_tag(asset_id, tag_id)
        logger.info("Added {0} with id {1} to asset {2}".format(tag_name, tag_id, asset_id))
    except rapid7vmconsole.rest.ApiException:
        logger.error("Failed to add {0} to ip {1}".format(tag_name, asset_id), exc_info=True)


def create_tag(tag):
    tag = { "name" : tag, "type" : "custom"}
    try:
        res = tag_api.create_tag(tag=tag)
        return res.id
    except rapid7vmconsole.rest.ApiException:
        logger.error("error creating {0} tag".format(tag),exc_info=True)

def remove_asset_tag(asset_id, tag_id):
    try:
        asset_api.remove_asset_tag(asset_id, tag_id)
        logger.info("Removed tag {0} from asset {1}".format(tag_id, asset_id))
    except rapid7vmconsole.rest.ApiException:
        logger.error("error removing tag {0} from asset {1}".format(tag_id, asset_id),exc_info=True)

def gen_device_tag_names(info):
    tags = []
    tags.append("Vendor: " + info.manufacturer)
    tags.append("Model: " + info.model_name)
    if info.firmware_version:
        tags.append("FW_Version: " + info.firmware_version)
    if info.latest_firmware_info and info.latest_firmware_info['version']:
        tags.append("LFW_Version: " + info.latest_firmware_info['version'])
    if info.is_discontinued:
        tags.append("Discontinued")
    if info.device_type:
        tags.append("Type: " + info.device_type)
    if info.firmware_info and info.latest_firmware_info and \
        info.firmware_info['release_date'] and info.latest_firmware_info['release_date']:
            try:
                fw_rel_date  = datetime.strptime(info.firmware_info['release_date'], "%Y-%m-%d")
                latest_fw_rel_date  = datetime.strptime(info.latest_firmware_info['release_date'], "%Y-%m-%d")
                if fw_rel_date < latest_fw_rel_date:
                    tags.append("Outdated_FW")
            except ValueError as e:
                logger.warning(e, exc_info=True)
                pass

    for cve in info.cve_list:
        tags.append(cve.cve_id)

    return tags


def add_tags(ip, tags):
    asset = find_asset(ip)
    if not asset:
        logger.warning("No insightvm asset was found for discovered host {0}".format(ip))
        return
    asset_id = asset.id
    curr_tags = get_asset_tags(asset_id)  # returns a dict
    for tag_name in tags:
        if tag_name in curr_tags:
            continue
        new_prefix = tag_name.split(':')[0]
        for key in curr_tags:
            curr_prefix = key.split(':')[0]
            if new_prefix == curr_prefix:
                logger.info("Updating tag {0} on {1}".format(key, ip))
                remove_asset_tag(asset_id, curr_tags[key])
                break
        tag_id = get_custom_tag(tag_name, asset_id)
        if not tag_id:
            tag_id = create_tag(tag_name)
        if tag_id:
            tag_asset(asset_id, tag_id, tag_name)
        else:
            logger.warning("Failed to add tags for ip: {0}".format(ip))

def get_firmware_risk(sha2):
    try:
        risk = firmware_api.get_risk(sha2)
        return risk
    except iotvas.rest.ApiException:
        logger.error("failed to fetch firmware risk for {0}".format(sha2), exc_info=True)

def gen_uname_tags(sha2, is_latest):
    prefix = "FW_Acct: "
    if is_latest:
        prefix = "L" + prefix
    try:
        usernames = []
        accounts = firmware_api.get_accounts(sha2)
        for account in accounts:
            if account.pwd_hash and account.pwd_hash != '*':
                usernames.append(prefix + account.name)
        return usernames
    except iotvas.rest.ApiException:
        logger.error("failed to fetch default accounts for {0}".format(sha2), exc_info=True)

def gen_crypto_key_tags(sha2, is_latest):
    prefix = "FW_Pkey: "
    if is_latest:
        prefix = "L" + prefix
    try:
        keys = []
        pkeys = firmware_api.get_private_keys(sha2)
        for key in pkeys:
            if key.algorithm and key.bits:
                keys.append("{0} {1}/{2}".format(prefix, key.algorithm, key.bits))
        return keys
    except iotvas.rest.ApiException:
        logger.error("failed to fetch private keys for {0}".format(sha2), exc_info=True)

def gen_weak_key_tags(sha2, is_latest):
    prefix = "FW_WKey: "
    if is_latest:
        prefix = "L" + prefix
    try:
        keys = []
        pkeys = firmware_api.get_weak_keys(sha2)
        for key in pkeys:
            if key.algorithm and key.bits:
                keys.append("{0} {1}/{2}".format(prefix, key.algorithm, key.bits))
        return keys
    except iotvas.rest.ApiException:
        logger.error("failed to fetch weak keys for {0}".format(sha2), exc_info=True)

 
def gen_weak_certalg_tags(sha2, is_latest):
    prefix = "FW_WCert: "
    if is_latest:
        prefix = "L" + prefix
    algs = []
    try:
        certs = firmware_api.get_weak_certs(sha2)
        for cert in certs:
            if cert.sign_algorithm:
                algs.append(prefix + cert.sign_algorithm)
        return algs
    except iotvas.rest.ApiException:
        logger.error("failed to fetch weak certs for {0}".format(sha2), exc_info=True)


def gen_firmware_tag_names(risk, is_latest):
    tags = []
    prefix = "FW_"
    if is_latest:
        prefix = "L" + prefix
    summary = risk.risk_summary
    for key in summary:
        if summary[key] != 'None':
            tags.append(prefix + key + ": " + summary[key])
    
    prefix = "FW"
    if is_latest:
        prefix = "L" + prefix
    for compo in risk.vulnerable_components:
        for vuln in compo.vulnerabilities:
            tags.append(prefix + ": " + vuln.cve_id)

    return tags

def parse_features_table(tbl):
    features = {
        "snmp_sysdescr": "",
        "snmp_sysoid": "",
        "ftp_banner": "",
        "telnet_banner": "",
        "hostname": "",
        "http_response": "",
        "https_response": "",
        "upnp_response": "",
        "nic_mac": ""
    }
    for elem in tbl.findall('elem'):
        key = elem.get('key')
        if key in features.keys() and elem.text:
            features[key] = elem.text
    return features


def parse_hosts_features(dom):
    for host in dom.findall("host"):
        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            if not ip:
                continue
        for hostscript in host.findall("hostscript"):
            for script in hostscript.findall("script"):
                _id = script.get("id")
                if _id == "iotvas-features":
                    tbl = script.find("table")
                    features = parse_features_table(tbl)
                    device_info = device_api.detect_device(features)
                    if not (device_info.manufacturer and device_info.model_name):
                        logger.info("device maker and model not found for {0}".format(ip))
                        continue
                    tag_names = gen_device_tag_names(device_info)
                    add_tags(ip, tag_names)
                    firmware_info = device_info.firmware_info
                    is_latest_fw = False
                    if not firmware_info:
                        firmware_info = device_info.latest_firmware_info
                        is_latest_fw = True
                    if firmware_info:
                        sha2 = firmware_info['sha2']
                        risk = get_firmware_risk(sha2)
                        if risk.risk_summary:
                            tag_names = gen_firmware_tag_names(risk, is_latest_fw)
                            add_tags(ip, tag_names)
                        tag_users = gen_uname_tags(sha2, is_latest_fw)
                        add_tags(ip, tag_users)
                        tag_pkeys = gen_crypto_key_tags(sha2, is_latest_fw)
                        add_tags(ip, tag_pkeys)
                        tag_wkeys = gen_weak_key_tags(sha2, is_latest_fw)
                        add_tags(ip, tag_wkeys)
                        tag_wcerts = gen_weak_certalg_tags(sha2, is_latest_fw)
                        add_tags(ip, tag_wcerts)


def parse_nmap_xml(xml):
    dom = ET.fromstring(xml)
    parse_hosts_features(dom)


def nmap_callback(nmap_proc):
    nmaptask = nmap_proc.current_task
    if nmaptask:
        logger.info("Task {0} ({1}): ETC: {2} DONE: {3}%".format(\
            nmaptask.name, nmaptask.status, nmaptask.etc, nmaptask.progress))


def scan_targets(targets, options):
    nm = NmapProcess(targets, options, event_callback=nmap_callback)
    logger.info("Starting nmap scan: {0}".format(nm.command))
    rc = nm.run()
    if rc != 0:
        logger.error("Nmap failed to start: {0}".format(nm.stderr))
    else:
        logger.info("Nmap scan completed")
        xml = nm.stdout
        parse_nmap_xml(xml)

def main(argv):
    parser = get_argparser()
    if len(argv) ==  1:
        parser.print_help(sys.stderr)
        exit(1)
    args = parser.parse_args()
    nmap_cmd = "-sSU -p U:161,T:- --top-ports 1000 --script iotvas-features.nse"
    if args.targets_file:
        targets = []
        with open(args.targets_file, "r") as fp:
            line = fp.readline()
            while line:
                targets.append(line.strip().rstrip('\n'))
                line = fp.readline()
        if args.excludes:
            nmap_cmd = nmap_cmd + " --excludefile " + args.excludes
        scan_targets(targets, nmap_cmd)

if __name__ == "__main__":
  main(sys.argv)
