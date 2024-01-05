from pysnmp.hlapi import (
    getCmd,
    bulkCmd,
    nextCmd,
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
)
import time
import json
import threading

# SNMP target device information
target = "192.168.1.8"  # IP address of the SNMP device
community = "public"  # SNMP community string for authentication


def get_snmp_data(oids, community, ip, port=161):
    """
    Fetch SNMP data for multiple OIDs.
    :param oids: List of OIDs to query.
    :param community: SNMP community string.
    :param ip: IP address of the target device.
    :param port: SNMP port, default is 161.
    :return: Dictionary of OID values.
    """
    engine = SnmpEngine()
    auth_data = CommunityData(community)
    transport = UdpTransportTarget((ip, port))
    context = ContextData()
    var_binds = [ObjectType(ObjectIdentity(oid)) for oid in oids]
    result_data = {}

    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(engine, auth_data, transport, context, *var_binds)
    )
    if errorIndication or errorStatus:
        print(f"SNMP Error: {errorIndication or errorStatus.prettyPrint()}")
        return None
    else:
        for varBind in varBinds:
            oid, value = varBind[0].prettyPrint(), varBind[1].prettyPrint()
            result_data[oid] = value
    return result_data


def get_bulk_snmp_data(oid, community, ip, port=161):
    """
    Fetch bulk SNMP data for a specified OID.
    :param oid: Base OID for the bulk request.
    :param community: SNMP community string.
    :param ip: IP address of the target device.
    :param port: SNMP port, default is 161.
    :return: Dictionary of OID values.
    """
    result_data = {}
    for errorIndication, errorStatus, errorIndex, varBinds in bulkCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, port)),
        ContextData(),
        0,
        25,  # Non-repeaters, max-repetitions
        ObjectType(ObjectIdentity(oid)),
    ):
        if errorIndication or errorStatus:
            print(f"Bulk SNMP Error: {errorIndication or errorStatus.prettyPrint()}")
            return None
        else:
            for varBind in varBinds:
                oid, value = varBind[0].prettyPrint(), varBind[1].prettyPrint()
                result_data[oid] = value
    return result_data


# Function to perform SNMP walk operation
def perform_snmp_walk(oid, community, ip, port=161):
    """
    Perform an SNMP walk to fetch all data under the specified OID.
    :param oid: Base OID for the SNMP walk.
    :param community: SNMP community string.
    :param ip: IP address of the target device.
    :param port: SNMP port, default is 161.
    :return: Dictionary of OID values.
    """
    result_data = {}
    for errorIndication, errorStatus, errorIndex, varBinds in nextCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, port)),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False,
    ):
        if errorIndication or errorStatus:
            print(f"SNMP Error: {errorIndication or errorStatus.prettyPrint()}")
            break
        else:
            for varBind in varBinds:
                oid, value = varBind[0].prettyPrint(), varBind[1].prettyPrint()
                result_data[oid] = value
    return result_data


# Function to get interface index based on the provided IP address
def get_interface_index(target, community, target_ip):
    """
    Retrieve the interface index for the given IP address.
    :param target: IP address of the target device.
    :param community: SNMP community string.
    :param target_ip: IP address to find the interface index for.
    :return: Interface index or None if not found.
    """
    oid = f"1.3.6.1.2.1.4.20.1.2.{target_ip}"
    result_data = get_snmp_data([oid], community, target)
    return list(result_data.values())[0] if result_data else None


first_iteration = True
processed_traffic_statistics = {}
facility = {}


def fetch_traffic_data(target, community):
    global first_iteration
    interface_index = get_interface_index(target, community, target)
    if interface_index:
        oids = [
            f"1.3.6.1.2.1.2.2.1.10.{interface_index}",  # Inbound traffic
            f"1.3.6.1.2.1.2.2.1.16.{interface_index}",  # Outbound traffic
        ]

        facility["in_predecessor"], facility["out_predecessor"] = list(
            get_snmp_data(oids, community, target).values()
        )

        time.sleep(1)

        traffic_data = get_snmp_data(oids, community, target)

        processed_traffic_statistics.update(
            {
                "in_current": (
                    int(list(traffic_data.values())[0], 0)
                    - int(facility["in_predecessor"])
                )
                * 8
                / 125e3,
                "out_current": (
                    int(list(traffic_data.values())[1], 0)
                    - int(facility["out_predecessor"])
                )
                * 8
                / 125e3,
            }
        )

        facility.update(
            {
                "in_total": facility.get("in_total", 0)
                + processed_traffic_statistics["in_current"],
                "out_total": facility.get("out_total", 0)
                + processed_traffic_statistics["out_current"],
                "total_traffic": facility.get("total_traffic", 0) + 1,
            }
        )

        processed_traffic_statistics.update(
            {
                "in_avg": (facility["in_total"] / facility["total_traffic"]),
                "out_avg": (facility["out_total"] / facility["total_traffic"]),
                "in_min": min(
                    processed_traffic_statistics.get("in_min", float("inf")),
                    processed_traffic_statistics["in_current"],
                ),
                "out_min": min(
                    processed_traffic_statistics.get("out_min", float("inf")),
                    processed_traffic_statistics["out_current"],
                ),
                "in_max": max(
                    processed_traffic_statistics.get("in_max", 0),
                    processed_traffic_statistics["in_current"],
                ),
                "out_max": max(
                    processed_traffic_statistics.get("out_max", 0),
                    processed_traffic_statistics["out_current"],
                ),
            }
        )

        facility.update(
            {
                "in_predecessor": list(traffic_data.values())[0],
                "out_predecessor": list(traffic_data.values())[1],
            }
        )

        print("Processed Traffic Statistics:", processed_traffic_statistics)
        print("Facility:", facility)

        return processed_traffic_statistics
    else:
        return {"error": "Interface index could not be determined."}


def fetch_system(target, community):
    system_data = perform_snmp_walk("1.3.6.1.2.1.1", community, target)
    return {"system_data": system_data}


def fetch_system_and_tcp_data(target, community):
    """Fetch detailed system and TCP connection table data."""
    system_data = perform_snmp_walk("1.3.6.1.2.1.1", community, target)
    tcp_data = get_bulk_snmp_data("1.3.6.1.2.1.6.13", community, target)
    return {"system_data": system_data, "tcp_connection_table": tcp_data}


def main():
    start_time = time.time()

    traffic_data = fetch_traffic_data(target, community)
    print("Traffic Data:", json.dumps(traffic_data, indent=4))

    detailed_data = fetch_system_and_tcp_data(target, community)
    print("Detailed Data:", json.dumps(detailed_data, indent=4))

    end_time = time.time()
    print(f"Execution Time: {end_time - start_time} seconds")


if __name__ == "__main__":
    main()
