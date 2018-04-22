import sys
from wsgiref.util import FileWrapper

from Crypto.SelfTest.PublicKey.test_import_ECC import load_file
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.core.files import File
from django.http import FileResponse, HttpResponseRedirect
from django.http import HttpResponse
import hashlib
if sys.version_info < (3,6):
    import sha3
import os, random, struct, tempfile
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

# Digital Signature Algorithm
from Crypto.Hash import SHA256, MD5
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


from django.contrib.auth.models import User

from securewebapp.forms import AESKeyForm, SignatureForm, VerifySignatureForm


# Create your views here.
from securewebapp.models import ExtendUser


@login_required
def home(request):
    context_dict = dict()
    user = User.objects.get(id=request.user.id)
    print(user.password)
    hsh_passwd = user.password
    hsh_passwd = hsh_passwd.split('$')
    salt = hsh_passwd[1]
    hsh = hsh_passwd[2]
    print(hsh)
    context_dict['aes_form'] = AESKeyForm()
    context_dict['signature_form'] = SignatureForm()
    context_dict['verify_signature_form'] = VerifySignatureForm()
    return render(request, 'home.html', context_dict)


@login_required
def aes_file_upload(request):
    context_dict = dict()
    if request.method == 'POST' and request.FILES['file_to_encrypt']:
        form = AESKeyForm(request.POST, request.FILES)
        if form.is_valid():
            myfile = request.FILES['file_to_encrypt']
            key_to_encrypt = form.cleaned_data['key']
            print(key_to_encrypt)

            # AES file encryption
            # key = get_random_bytes(16)
            #key = hashlib.sha256(request.user.password.encode('utf-8')).digest()
            key = hashlib.sha3_256(key_to_encrypt.encode('utf-8')).digest()
            cipher = AES.new(key, AES.MODE_EAX)
        #    data = "I met aliens in UFO. Here is the map.".encode("utf-8")
            ciphertext, tag = cipher.encrypt_and_digest(myfile.read())
            print(cipher)
            print(tag)

            file_out = open("encrypted.bin", "wb")
            [file_out.write(x) for x in (cipher.nonce, tag, ciphertext)]

            # encoded = [x for x in (cipher.nonce, tag, ciphertext)]
            file_out.close()
            print('encrypting completed')

            # file_in = open("encrypted.bin", "rb")

            # euser = request.user.extenduser
            # euser.submitted_file = myfile
            # encrypted_f = File(file_in)
            # euser.aes_encrypted_file = encrypted_f
            # euser.save()

            tmp = tempfile.NamedTemporaryFile(prefix='aes_encrypted')
            try:
                # tmp = tempfile.NamedTemporaryFile(delete=False)
                with open(tmp.name, 'wb') as fi:
                    [fi.write(x) for x in (cipher.nonce, tag, ciphertext)]
                response = FileResponse(open(tmp.name, 'rb'))
                response['content_type'] = 'plain/text'
                return HttpResponse(response, content_type='plain/text')
            finally:
                tmp.close()
                # os.remove(tmp.name)
        else:
            print(form.errors)
    return render(request, 'home.html', context_dict)


def aes_file_decrypt(request):
    context_dict = dict()
    if request.method == 'POST' and request.FILES['file_to_encrypt']:
        form = AESKeyForm(request.POST, request.FILES)
        if form.is_valid():
            myfile = request.FILES['file_to_encrypt']

            key_to_encrypt = form.cleaned_data['key']
            key = hashlib.sha3_256(key_to_encrypt.encode('utf-8')).digest()
            file_out = open("encrypted.bin", "wb")
            [file_out.write(x) for x in myfile]
            file_out.close()
            tmp = tempfile.NamedTemporaryFile(delete=False)
            try:
                tmp = tempfile.NamedTemporaryFile(delete=False)
                file_in = open(file_out.name, "rb")
                nonce, tag, ciphertext = [file_in.read(x) for x in (16, 16, -1)]
                cipher = AES.new(key, AES.MODE_EAX, nonce)
                try:
                    data = cipher.decrypt_and_verify(ciphertext, tag)
                except Exception as e:
                    print('something fuck up')
                    return HttpResponse('The message has been tampered with or the key is incorrect.')

                with open(tmp.name, 'w') as fi:
                    fi.write(data.decode("utf-8"))

                response = FileResponse(open(tmp.name, 'rb'))
                response['content_type'] = 'plain/text'
                return HttpResponse(response, content_type='plain/text')
            finally:
                pass
                # os.remove(tmp.name)

        return render(request, 'home.html', context_dict)


@login_required
def generate_digital_signature(request):
    """
    1. generate public and private key
    2. signature upload file and return a signed file which i the original file + signature.
       i.e. hash of the encrypted file + private key

    :param request:
    :return:
    """
    context_dict = dict()
    if request.method == 'POST' and request.FILES['file_to_sign']:
        form = SignatureForm(request.POST, request.FILES)
        if form.is_valid():
            # myfile = request.FILES['file_to_sign']
            myfile = form.cleaned_data.get('file_to_sign')
            file_out = open("privkey.pem", "w")
            [file_out.write(x) for x in (request.user.extenduser.private_key)]
            file_out.close()

            # ECC way of signing - not ging to use it
            # key = ECC.generate(curve='P-256')
            # f = open('myprivatekey.pem', 'wt')
            # f.write(key.export_key(format='PEM'))
            # f.close()
            # f = open('myprivatekey.pem', 'rt')
            # key = ECC.import_key(f.read())
            # h = SHA256.new(myfile.read())
            # signer = DSS.new(key, 'fips-186-3')
            # signature = signer.sign(h)

            f = open('myRSAkey.pem', 'r')
            key = RSA.import_key(f.read())
            myfile_read = myfile.read()
            # h = MD5.new(myfile.read())
            h = MD5.new(myfile_read)
            signature = pss.new(key).sign(h)

            # now we want to create a new file with the signature + hash of encrypted file (submitted by user)
            file_out = open("signedDoc", "wb")
            [file_out.write(x) for x in (signature, myfile_read)]
            file_out.close()

            tmp = tempfile.NamedTemporaryFile(delete=False)
            try:
                tmp = tempfile.NamedTemporaryFile(delete=False)
                with open(tmp.name, 'wb') as fi:
                    [fi.write(x) for x in (signature, myfile_read)]
                response = FileResponse(open(file_out.name, 'rb'))
                response['content_type'] = 'plain/text'
                return HttpResponse(response, content_type='plain/text')
            finally:
                pass
                # os.remove(tmp.name)

            # Sanity check for resulting document
            file_in = open("signedDoc", "rb")
            obtained_signature, org_doc = [file_in.read(x) for x in (256, -1)]
            if obtained_signature == signature:
                print("we fucking rule !!!!")

            # verify signature
            pub_key = RSA.import_key(open('myPUBkey.pem').read())

            hed = MD5.new(myfile_read)
            verifier = pss.new(pub_key)
            try:
                verifier.verify(hed, obtained_signature)
                print("The signature is authentic.")
            except (ValueError, TypeError):
                print("The signature is not authentic.")
            file_in.close()

            # simple sanity check
            # message = b'to be signed'
            # m_h = MD5.new(message)
            # firma = pss.new(key).sign(m_h)
            #
            # m_h2 = MD5.new(message)
            # verr = pss.new(pub_key)
            # try:
            #     verr.verify(m_h2, firma)
            #     print("The real deal nigga!!")
            # except (ValueError, TypeError):
            #     print("The signature is not authentic.")
            print('blancas')
    return render(request, 'home.html', context_dict)


@login_required
def download_public_key(request):
    p = open('myPUBkey.pem', 'r')

    tmp = tempfile.NamedTemporaryFile(delete=False)
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False)
        with open(tmp.name, 'w') as fi:
            fi.write(p.read())
        response = FileResponse(open(tmp.name, 'rb'))
        response['content_type'] = 'plain/text'
        return HttpResponse(response, content_type='plain/text')
    finally:
        pass
        # os.remove(tmp.name)
    pass


@login_required
def verify_digital_signature(request):
    context_dict = dict()
    if request.method == 'POST' and request.FILES['file_to_verify'] and request.FILES['public_key']:
        form = VerifySignatureForm(request.POST, request.FILES)
        if form.is_valid():
            file_to_verify = form.cleaned_data.get('file_to_verify')
            public_key_file = form.cleaned_data.get('public_key')
            file_out = open("tempubkey.pem", "wb")
            [file_out.write(x) for x in public_key_file]
            file_out.close()
            public_key = open(file_out.name, "rb")
            try:
                pub_key = RSA.import_key(public_key.read())
            except (ValueError, TypeError):
                print("The signature is not authentic.")
                return HttpResponseRedirect(reverse('not_authentic'), context_dict)

            db_pub_key = RSA.import_key(request.user.extenduser.public_key)

            p = open('myPUBkey.pem', 'r')
            stored_pubkey = RSA.import_key(p.read())

            if pub_key == db_pub_key:
                print("we got it")
            elif stored_pubkey == pub_key:

                print('stored_pubkey == pub_key equal')
            elif stored_pubkey == db_pub_key:
                print('stored_pubkey == db_pub_key  equal')
            else:
                print(pub_key)
                print(db_pub_key)

            myfile_read = file_to_verify.read()
            usrfile_out = open("tempupuser", "wb")
            [usrfile_out.write(x) for x in (myfile_read,)]
            usrfile_out.close()

            verifier = pss.new(pub_key)
            file_in = open(usrfile_out.name, "rb")
            obtained_signature, org_doc = [file_in.read(x) for x in (256, -1)]
            hed = MD5.new(org_doc)
            try:
                verifier.verify(hed, obtained_signature)
                print("The signature is authentic.")
                return HttpResponseRedirect(reverse('authentic'), context_dict)
            except (ValueError, TypeError):
                print("The signature is not authentic.")
                return HttpResponseRedirect(reverse('not_authentic'), context_dict)
    return render(request, 'home.html', context_dict)


@login_required
def authentic(request):
    return render(request, 'authentic.html')


@login_required
def not_authentic(request):
    return render(request, 'not-authentic.html')


def generate_keys():
    # public and private key geneator
    key = RSA.generate(2048)
    public_key = key.publickey().exportKey("PEM")
    private_key = key.exportKey("PEM")
    f = open('myRSAkey.pem', 'wb')
    f.write(private_key)
    f.close()
    p = open('myPUBkey.pem', 'wb')
    p.write(public_key)
    p.close()
    return public_key, private_key

