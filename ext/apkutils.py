"""
Classes, helpers and methods for working with .apk files
"""
import datetime

from asn1crypto import x509
from pyaxmlparser import APK


class PermissionAnalyzer:
    """
    Checks for unusual or dangerous permissions
    """
    android_permissions = []
    third_party_permissions = []

    security_pool = {
        "low_risk": [
            "READ_EXTERNAL_STORAGE",
            "WRITE_EXTERNAL_STORAGE",
            "RECEIVE_BOOT_COMPLETED",
            "GET_ACCOUNTS",
            "RECORD_AUDIO",
            "MANAGE_DOCUMENTS",
            "REQUEST_INSTALL_PACKAGES",
            "ACCESS_BACKGROUND_LOCATION",
            "BLUETOOTH_ADMIN"
        ],
        "high_risk": [
            "DISABLE_KEYGUARD",
            "KILL_BACKGROUND_PROCESSES",
            "REQUEST_DELETE_PACKAGES",
            "READ_CONTACTS",
            "ANSWER_PHONE_CALLS",
            "SEND_SMS"
        ]
    }

    def __init__(self, permission_list):
        """
        Set the list of permissions
        :param permission_list:
        """
        for permission in permission_list:
            if permission.startswith("android.permission."):
                self.android_permissions.append(
                    permission.replace("android.permission.", "")
                )
            else:
                self.third_party_permissions.append(permission)

    def get_security_opt(self, permission):
        """
        Return the list and check if unusual or dangerous
        :param permission:
        :return:
        """
        for sec_opt in self.security_pool:
            for get_permission in self.security_pool[sec_opt]:
                if get_permission in permission:
                    return sec_opt
        return None

    def parse_list(self):
        """
        Return the output
        :return:
        """
        output = {}
        for permission in self.android_permissions:
            output.update({permission: self.get_security_opt(permission)})
        return output


def process(apk_file):
    """
    Process the APK and run various security checks
    :param apk_file:
    :return:
    """
    apk_file_data = APK(apk_file)
    security = {}

    security.update(permissions=PermissionAnalyzer(apk_file_data.get_permissions()).parse_list())

    verification = {}
    verification.update(signed_v1=apk_file_data.is_signed_v1())
    verification.update(signed_v2=apk_file_data.is_signed_v2())
    verification.update(signed_v3=apk_file_data.is_signed_v3())
    security.update(signatures=verification)

    certificates = {}
    certs: x509.Certificate = apk_file_data.get_certificates()
    for certificate in certs:
        certificate: x509.Certificate = certificate
        cert_output = {}
        cert_output.update(dict(hash_algo=certificate.hash_algo))
        cert_output.update(dict(issuer=certificate.issuer.native))
        cert_output.update(dict(self_issued=certificate.self_issued))
        cert_output.update(dict(self_signed=certificate.self_signed))
        cert_output.update(dict(signature_algo=certificate.signature_algo))

        cert_output.update(dict(
            valid_until=certificate.not_valid_after.strftime("%m/%d/%Y, %H:%M:%S")
        ))
        cert_output.update(dict(
            is_valid=certificate.not_valid_before <= datetime.datetime.now(
                certificate.not_valid_before.tzinfo
            ) <= certificate.not_valid_after)
        )

        certificates[certificate.serial_number] = cert_output

    security.update(certificates=certificates)

    common = {}

    common.update(dict(name=apk_file_data.application))
    common.update(dict(package=apk_file_data.packagename))
    common.update(dict(version_name=apk_file_data.version_name))
    common.update(dict(version_code=apk_file_data.version_code))
    common.update(dict(
        icon_data=apk_file_data.icon_info
    ))
    application_data = dict(security=security, common=common)
    return application_data
