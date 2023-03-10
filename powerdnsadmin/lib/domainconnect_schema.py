from lima import fields, Schema


class DomainConnectSettingsSchema(Schema):
    providerId = fields.String(key="providerId")
    providerName = fields.String(key="providerName")
    providerDisplayName = fields.String(key="providerDisplayName")
    urlSyncUX = fields.String(key="urlSyncUX")
    # urlAsyncUX = fields.String(key="urlAsyncUX") // not supported now
    urlAPI = fields.String(key="urlAPI")
    width = fields.Integer(key="width")
    height = fields.Integer(key="height")
    urlControlPanel = fields.String(key="urlControlPanel")


