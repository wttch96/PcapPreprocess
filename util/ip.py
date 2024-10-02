import ipaddress


def get_ip_class(ip_address: str) -> str:
    """
    获取 IP 地址所属的 ABCD 类.
    Args:
        ip_address: ip 地址
    Returns:
        str: IP 地址所属的 ABCD 类
    Raises:
        ValueError: 可能会在处理的过程中出现的异常
    """
    ip = ipaddress.ip_address(ip_address)
    first_byte = ip.packed[0]
    if first_byte < 128:
        return 'A'
    elif first_byte < 192:
        return 'B'
    elif first_byte < 224:
        return 'C'
    elif first_byte < 240:
        return 'D'
    else:
        return 'E'
