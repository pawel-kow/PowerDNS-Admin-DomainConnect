from lima import fields, Schema


'''
{
    "providerId": "virtucondomains.com",
    "providerName": "Virtucon Domains",
    "providerDisplayName": "Virtucon Domains",
    "urlSyncUX": "https://domainconnect.virtucondomains.com",
    "urlAsyncUX": "https://domainconnect.virtucondomains.com",
    "urlAPI": "https://api.domainconnect.virtucondomains.com",
    "width": 750,
    "height": 750,
    "urlControlPanel": "https://domaincontrolpanel.virtucondomains.com/?domain=%domain%",
    "nameServers": ["ns01.virtucondomainsdns.com", "ns02.virtucondomainsdns.com"]
}
'''

class DomainConnectSettingsSchema(Schema):
    providerId = fields.String()
    name = fields.String()

