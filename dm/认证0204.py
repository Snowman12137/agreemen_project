# 实现用户与基站间的认证
# 协议的实现：33501-g20 6.1.3.1 EAP-AKA身份验证程序

class Udm:

    def __init__(self):
        self.AV = None
        self.indication = None

    def generate_AV(self):      # 生成认证向量。
        #SQN =
        AMF = b'\x70\x00'      # 最高分离位是1。1~7保留位置0。8~15专用。未知，置0.
        RAND, AUTN, XRES, CK, IK = [None] * 5
        self.AV = {'RAND': RAND, 'AUTN': AUTN, 'XRES': XRES, 'CK': CK, 'IK': IK}
        pass

    def send_AV(self, AUSF):        # 将AV'发送到AUSF
        AUSF.AV = self.AV
        print("AUSF接收到UDM发送的AV'：", AUSF.AV)


class Ausf:

    def __init__(self):
        self.AV = None
        self.Nausf_UEAuthentication_Authenticate_Response = {'EAP Requset': None}
        self.EAP_Request = None         # EAP-AKA包含在Nausf_UEAuthentication_Authenticate_Response中
        self.Nausf_UEAuthentication_Authenticate_Request = {'EAP Response': None}

    def send_Nudm_UEAuthentication_Get_Request(self, UDM):
        indication = "AV' is to be used for EAP-AKA' using a Nudm_UEAuthentication_Get Response message."
        UDM.indication = indication
        print("UDM接收到AUSF返回的Nudm_UEAuthentication_Get Response消息：", UDM.indication)
        if UDM.indication == "AV' is to be used for EAP-AKA' using a Nudm_UEAuthentication_Get Response message.":
            print("此认证向量将被用于EAP-AKA认证。")
        else:
            print("未知错误")

    def send_Nausf_UEAuthentication_Authenticate_Response(self, SEAF):
        SEAF.Nausf_UEAuthentication_Authenticate_Response = self.Nausf_UEAuthentication_Authenticate_Response
        print("SEAF接收到AUSF的质询消息：", SEAF.Nausf_UEAuthentication_Authenticate_Response)

    def verify_Resp(self):
        print("接收到EAP_Resp，进行新鲜性检查...")
        check = self.Nausf_UEAuthentication_Authenticate_Request

        '''
        检查过程
        '''

        result = None
        if result == True:
            print("检查完毕，认证成功！")
        else:
            print("未知错误，无法认证！")

class Seaf:

    def __init__(self):
        self.Nausf_UEAuthentication_Authenticate_Response = None
        self.EAP_Req = None
        self.ngKSI = None
        self.ABBA = None
        self.Auth_Req = {'EAP Request': self.EAP_Req, 'nkKSI': self.ngKSI, 'ABBA': self.ABBA}
        self.Auth_Resp = None
        self.Nausf_UEAuthentication_Authenticate_Request = None

    def forwd_Auth_Req(self, UE):
        UE.Auth_Req = self.Auth_Req
        print("SEAF向UE转发Auth_Req：", UE.Auth_Req)

    def forwd_Nausf_UEAuthentication_Authenticate_Request(self, AUSF):
        AUSF.Nausf_UEAuthentication_Authenticate_Request = self.Nausf_UEAuthentication_Authenticate_Request
        print("SEAF向AUSF转发EAP_Request：", AUSF.EAP_Request)



class Ue:

    def __init__(self):
        self.Auth_Req = None
        self.EAP_Resp = None
        self.Auth_Resp = (self.EAP_Resp, )

    def calculate_Auth_Resp(self):
        print("UE从Auth-Req中计算Auth-Resp...")

        '''
        计算过程
        '''

        self.Auth_Resp = {'EAP_Resp': self.EAP_Resp}
        print("计算结果是：", UE.Auth_Resp)

    def send_Auth_Resp(self, SEAF):
        SEAF.Auth_Resp = self.Auth_Resp
        print("SEAF接收到UE的Auth_Resp：", SEAF.Auth_Resp)

# 生成四个部件的实例
UDM = Udm()
AUSF = Ausf()
SEAF = Seaf()
UE = Ue()

# 1.生成AV
# AMF在33102附件H
UDM.generate_AV()

# 2.将AV发送到AUSF,AUSF向UDM发送带有indication的Nudm_UEAuthentication_Get_Request
UDM.send_AV(AUSF)
AUSF.send_Nudm_UEAuthentication_Get_Request(UDM)
print(UDM.indication)

# 3.AUSF向SEAF发送EAP-Request
AUSF.send_Nausf_UEAuthentication_Authenticate_Response(SEAF)

# 4.SEAF将EAP请求转发给UE
SEAF.forwd_Auth_Req(UE)

# 5.UE收到Auth-Req，USIM计算Auth_Response
UE.calculate_Auth_Resp()

# 6.Ue向SEAF发送EAP响应消息
UE.send_Auth_Resp(SEAF)

# 7.SEAF将EAP响应(在Nausf请求中)转发给AUSF
SEAF.forwd_Nausf_UEAuthentication_Authenticate_Request(AUSF)

# 8.AUSF验证该消息
AUSF.verify_Resp()


