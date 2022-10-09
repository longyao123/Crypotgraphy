from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key,public_key

def sign(message, private):
    message = bytes(str(message),'utf-8') #converting message to bytes
    signature = private.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify(message,sign, publick):
    message = bytes(str(message),'utf-8')
    try:
        publick.verify(
            sign,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except:
        print("Error executing public key")
        return False

    



if __name__ == '__main__':
    prk,puk = generate_keys()
    # print(prk)
    # print(puk)

    message = "Hi, this is me trying crypto"
    sign = sign(message,prk)
    # print(sign)
    correct = verify(message,sign,puk)
    if correct:
        print("Successfull")
    else:
        print("Failed")
