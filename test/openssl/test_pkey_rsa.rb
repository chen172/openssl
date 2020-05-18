# frozen_string_literal: true
require_relative "utils"

if defined?(OpenSSL)

class OpenSSL::TestPKeyRSA < OpenSSL::PKeyTestCase
  def test_no_private_exp
    key = OpenSSL::PKey::RSA.new
    rsa = Fixtures.pkey("rsa2048")
    key.set_key(rsa.n, rsa.e, nil)
    key.set_factors(rsa.p, rsa.q)
    assert_raise(OpenSSL::PKey::RSAError){ key.private_encrypt("foo") }
    assert_raise(OpenSSL::PKey::RSAError){ key.private_decrypt("foo") }
  end

  def test_padding
    key = OpenSSL::PKey::RSA.new(512, 3)

    # Need right size for raw mode
    plain0 = "x" * (512/8)
    cipher = key.private_encrypt(plain0, OpenSSL::PKey::RSA::NO_PADDING)
    plain1 = key.public_decrypt(cipher, OpenSSL::PKey::RSA::NO_PADDING)
    assert_equal(plain0, plain1)

    # Need smaller size for pkcs1 mode
    plain0 = "x" * (512/8 - 11)
    cipher1 = key.private_encrypt(plain0, OpenSSL::PKey::RSA::PKCS1_PADDING)
    plain1 = key.public_decrypt(cipher1, OpenSSL::PKey::RSA::PKCS1_PADDING)
    assert_equal(plain0, plain1)

    cipherdef = key.private_encrypt(plain0) # PKCS1_PADDING is default
    plain1 = key.public_decrypt(cipherdef)
    assert_equal(plain0, plain1)
    assert_equal(cipher1, cipherdef)

    # Failure cases
    assert_raise(ArgumentError){ key.private_encrypt() }
    assert_raise(ArgumentError){ key.private_encrypt("hi", 1, nil) }
    assert_raise(OpenSSL::PKey::RSAError){ key.private_encrypt(plain0, 666) }
  end

  def test_private
    # Generated by key size and public exponent
    key = OpenSSL::PKey::RSA.new(512, 3)
    assert(key.private?)

    # Generated by DER
    key2 = OpenSSL::PKey::RSA.new(key.to_der)
    assert(key2.private?)

    # public key
    key3 = key.public_key
    assert(!key3.private?)

    # Generated by public key DER
    key4 = OpenSSL::PKey::RSA.new(key3.to_der)
    assert(!key4.private?)
    rsa1024 = Fixtures.pkey("rsa1024")

    # Generated by RSA#set_key
    key5 = OpenSSL::PKey::RSA.new
    key5.set_key(rsa1024.n, rsa1024.e, rsa1024.d)
    assert(key5.private?)

    # Generated by RSA#set_key, without d
    key6 = OpenSSL::PKey::RSA.new
    key6.set_key(rsa1024.n, rsa1024.e, nil)
    assert(!key6.private?)
  end

  def test_new
    key = OpenSSL::PKey::RSA.new 512
    pem  = key.public_key.to_pem
    OpenSSL::PKey::RSA.new pem
    assert_equal([], OpenSSL.errors)
  end

  def test_new_exponent_default
    assert_equal(65537, OpenSSL::PKey::RSA.new(512).e)
  end

  def test_new_with_exponent
    1.upto(30) do |idx|
      e = (2 ** idx) + 1
      key = OpenSSL::PKey::RSA.new(512, e)
      assert_equal(e, key.e)
    end
  end

  def test_generate
    key = OpenSSL::PKey::RSA.generate(512, 17)
    assert_equal 512, key.n.num_bits
    assert_equal 17, key.e
    assert_not_nil key.d
  end

  def test_new_break
    assert_nil(OpenSSL::PKey::RSA.new(1024) { break })
    assert_raise(RuntimeError) do
      OpenSSL::PKey::RSA.new(1024) { raise }
    end
  end

  def test_sign_verify
    rsa1024 = Fixtures.pkey("rsa1024")
    data = "Sign me!"
    signature = rsa1024.sign("SHA1", data)
    assert_equal true, rsa1024.verify("SHA1", signature, data)

    signature0 = (<<~'end;').unpack("m")[0]
      oLCgbprPvfhM4pjFQiDTFeWI9Sk+Og7Nh9TmIZ/xSxf2CGXQrptlwo7NQ28+
      WA6YQo8jPH4hSuyWIM4Gz4qRYiYRkl5TDMUYob94zm8Si1HxEiS9354tzvqS
      zS8MLW2BtNPuTubMxTItHGTnOzo9sUg0LAHVFt8kHG2NfKAw/gQ=
    end;
    assert_equal true, rsa1024.verify("SHA256", signature0, data)
    signature1 = signature0.succ
    assert_equal false, rsa1024.verify("SHA256", signature1, data)
  end

  def test_sign_verify_options
    key = Fixtures.pkey("rsa1024")
    data = "Sign me!"
    pssopts = {
      "rsa_padding_mode" => "pss",
      "rsa_pss_saltlen" => 20,
      "rsa_mgf1_md" => "SHA1"
    }
    sig_pss = key.sign("SHA256", data, pssopts)
    assert_equal 128, sig_pss.bytesize
    assert_equal true, key.verify("SHA256", sig_pss, data, pssopts)
    assert_equal true, key.verify_pss("SHA256", sig_pss, data,
                                      salt_length: 20, mgf1_hash: "SHA1")
    # Defaults to PKCSv1.5 padding => verification failure
    assert_equal false, key.verify("SHA256", sig_pss, data)
  end

  def test_verify_empty_rsa
    rsa = OpenSSL::PKey::RSA.new
    assert_raise(OpenSSL::PKey::PKeyError, "[Bug #12783]") {
      rsa.verify("SHA1", "a", "b")
    }
  end

  def test_sign_verify_pss
    key = Fixtures.pkey("rsa1024")
    data = "Sign me!"
    invalid_data = "Sign me?"

    signature = key.sign_pss("SHA256", data, salt_length: 20, mgf1_hash: "SHA1")
    assert_equal 128, signature.bytesize
    assert_equal true,
      key.verify_pss("SHA256", signature, data, salt_length: 20, mgf1_hash: "SHA1")
    assert_equal true,
      key.verify_pss("SHA256", signature, data, salt_length: :auto, mgf1_hash: "SHA1")
    assert_equal false,
      key.verify_pss("SHA256", signature, invalid_data, salt_length: 20, mgf1_hash: "SHA1")

    signature = key.sign_pss("SHA256", data, salt_length: :digest, mgf1_hash: "SHA1")
    assert_equal true,
      key.verify_pss("SHA256", signature, data, salt_length: 32, mgf1_hash: "SHA1")
    assert_equal true,
      key.verify_pss("SHA256", signature, data, salt_length: :auto, mgf1_hash: "SHA1")
    assert_equal false,
      key.verify_pss("SHA256", signature, data, salt_length: 20, mgf1_hash: "SHA1")

    signature = key.sign_pss("SHA256", data, salt_length: :max, mgf1_hash: "SHA1")
    assert_equal true,
      key.verify_pss("SHA256", signature, data, salt_length: 94, mgf1_hash: "SHA1")
    assert_equal true,
      key.verify_pss("SHA256", signature, data, salt_length: :auto, mgf1_hash: "SHA1")

    assert_raise(OpenSSL::PKey::RSAError) {
      key.sign_pss("SHA256", data, salt_length: 95, mgf1_hash: "SHA1")
    }
  end

  def test_encrypt_decrypt
    rsapriv = Fixtures.pkey("rsa-1")
    rsapub = dup_public(rsapriv)

    # Defaults to PKCSv1
    raw = "data"
    enc = rsapub.encrypt(raw)
    assert_equal raw, rsapriv.decrypt(enc)

    # Invalid options
    assert_raise(OpenSSL::PKey::PKeyError) {
      rsapub.encrypt(raw, { "nonexistent" => "option" })
    }
  end

  def test_encrypt_decrypt_legacy
    rsapriv = Fixtures.pkey("rsa-1")
    rsapub = dup_public(rsapriv)

    # Defaults to PKCSv1
    raw = "data"
    enc_legacy = rsapub.public_encrypt(raw)
    assert_equal raw, rsapriv.decrypt(enc_legacy)
    enc_new = rsapub.encrypt(raw)
    assert_equal raw, rsapriv.private_decrypt(enc_new)

    # OAEP with default parameters
    raw = "data"
    enc_legacy = rsapub.public_encrypt(raw, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
    assert_equal raw, rsapriv.decrypt(enc_legacy, { "rsa_padding_mode" => "oaep" })
    enc_new = rsapub.encrypt(raw, { "rsa_padding_mode" => "oaep" })
    assert_equal raw, rsapriv.private_decrypt(enc_legacy, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
  end

  def test_export
    rsa1024 = Fixtures.pkey("rsa1024")
    key = OpenSSL::PKey::RSA.new

    # key has only n, e and d
    key.set_key(rsa1024.n, rsa1024.e, rsa1024.d)
    assert_equal rsa1024.public_key.export, key.export

    # key has only n, e, d, p and q
    key.set_factors(rsa1024.p, rsa1024.q)
    assert_equal rsa1024.public_key.export, key.export

    # key has n, e, d, p, q, dmp1, dmq1 and iqmp
    key.set_crt_params(rsa1024.dmp1, rsa1024.dmq1, rsa1024.iqmp)
    assert_equal rsa1024.export, key.export
  end

  def test_to_der
    rsa1024 = Fixtures.pkey("rsa1024")
    key = OpenSSL::PKey::RSA.new

    # key has only n, e and d
    key.set_key(rsa1024.n, rsa1024.e, rsa1024.d)
    assert_equal rsa1024.public_key.to_der, key.to_der

    # key has only n, e, d, p and q
    key.set_factors(rsa1024.p, rsa1024.q)
    assert_equal rsa1024.public_key.to_der, key.to_der

    # key has n, e, d, p, q, dmp1, dmq1 and iqmp
    key.set_crt_params(rsa1024.dmp1, rsa1024.dmq1, rsa1024.iqmp)
    assert_equal rsa1024.to_der, key.to_der
  end

  def test_RSAPrivateKey
    rsa1024 = Fixtures.pkey("rsa1024")
    asn1 = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(0),
      OpenSSL::ASN1::Integer(rsa1024.n),
      OpenSSL::ASN1::Integer(rsa1024.e),
      OpenSSL::ASN1::Integer(rsa1024.d),
      OpenSSL::ASN1::Integer(rsa1024.p),
      OpenSSL::ASN1::Integer(rsa1024.q),
      OpenSSL::ASN1::Integer(rsa1024.dmp1),
      OpenSSL::ASN1::Integer(rsa1024.dmq1),
      OpenSSL::ASN1::Integer(rsa1024.iqmp)
    ])
    key = OpenSSL::PKey::RSA.new(asn1.to_der)
    assert_predicate key, :private?
    assert_same_rsa rsa1024, key

    pem = <<~EOF
    -----BEGIN RSA PRIVATE KEY-----
    MIICXgIBAAKBgQDLwsSw1ECnPtT+PkOgHhcGA71nwC2/nL85VBGnRqDxOqjVh7Cx
    aKPERYHsk4BPCkE3brtThPWc9kjHEQQ7uf9Y1rbCz0layNqHyywQEVLFmp1cpIt/
    Q3geLv8ZD9pihowKJDyMDiN6ArYUmZczvW4976MU3+l54E6lF/JfFEU5hwIDAQAB
    AoGBAKSl/MQarye1yOysqX6P8fDFQt68VvtXkNmlSiKOGuzyho0M+UVSFcs6k1L0
    maDE25AMZUiGzuWHyaU55d7RXDgeskDMakD1v6ZejYtxJkSXbETOTLDwUWTn618T
    gnb17tU1jktUtU67xK/08i/XodlgnQhs6VoHTuCh3Hu77O6RAkEA7+gxqBuZR572
    74/akiW/SuXm0SXPEviyO1MuSRwtI87B02D0qgV8D1UHRm4AhMnJ8MCs1809kMQE
    JiQUCrp9mQJBANlt2ngBO14us6NnhuAseFDTBzCHXwUUu1YKHpMMmxpnGqaldGgX
    sOZB3lgJsT9VlGf3YGYdkLTNVbogQKlKpB8CQQDiSwkb4vyQfDe8/NpU5Not0fII
    8jsDUCb+opWUTMmfbxWRR3FBNu8wnym/m19N4fFj8LqYzHX4KY0oVPu6qvJxAkEA
    wa5snNekFcqONLIE4G5cosrIrb74sqL8GbGb+KuTAprzj5z1K8Bm0UW9lTjVDjDi
    qRYgZfZSL+x1P/54+xTFSwJAY1FxA/N3QPCXCjPh5YqFxAMQs2VVYTfg+t0MEcJD
    dPMQD5JX6g5HKnHFg2mZtoXQrWmJSn7p8GJK8yNTopEErA==
    -----END RSA PRIVATE KEY-----
    EOF
    key = OpenSSL::PKey::RSA.new(pem)
    assert_same_rsa rsa1024, key

    assert_equal asn1.to_der, rsa1024.to_der
    assert_equal pem, rsa1024.export
  end

  def test_RSAPrivateKey_encrypted
    rsa1024 = Fixtures.pkey("rsa1024")
    # key = abcdef
    pem = <<~EOF
    -----BEGIN RSA PRIVATE KEY-----
    Proc-Type: 4,ENCRYPTED
    DEK-Info: AES-128-CBC,733F5302505B34701FC41F5C0746E4C0

    zgJniZZQfvv8TFx3LzV6zhAQVayvQVZlAYqFq2yWbbxzF7C+IBhKQle9IhUQ9j/y
    /jkvol550LS8vZ7TX5WxyDLe12cdqzEvpR6jf3NbxiNysOCxwG4ErhaZGP+krcoB
    ObuL0nvls/+3myy5reKEyy22+0GvTDjaChfr+FwJjXMG+IBCLscYdgZC1LQL6oAn
    9xY5DH3W7BW4wR5ttxvtN32TkfVQh8xi3jrLrduUh+hV8DTiAiLIhv0Vykwhep2p
    WZA+7qbrYaYM8GLLgLrb6LfBoxeNxAEKiTpl1quFkm+Hk1dKq0EhVnxHf92x0zVF
    jRGZxAMNcrlCoE4f5XK45epVZSZvihdo1k73GPbp84aZ5P/xlO4OwZ3i4uCQXynl
    jE9c+I+4rRWKyPz9gkkqo0+teJL8ifeKt/3ab6FcdA0aArynqmsKJMktxmNu83We
    YVGEHZPeOlyOQqPvZqWsLnXQUfg54OkbuV4/4mWSIzxFXdFy/AekSeJugpswMXqn
    oNck4qySNyfnlyelppXyWWwDfVus9CVAGZmJQaJExHMT/rQFRVchlmY0Ddr5O264
    gcjv90o1NBOc2fNcqjivuoX7ROqys4K/YdNQ1HhQ7usJghADNOtuLI8ZqMh9akXD
    Eqp6Ne97wq1NiJj0nt3SJlzTnOyTjzrTe0Y+atPkVKp7SsjkATMI9JdhXwGhWd7a
    qFVl0owZiDasgEhyG2K5L6r+yaJLYkPVXZYC/wtWC3NEchnDWZGQcXzB4xROCQkD
    OlWNYDkPiZioeFkA3/fTMvG4moB2Pp9Q4GU5fJ6k43Ccu1up8dX/LumZb4ecg5/x
    -----END RSA PRIVATE KEY-----
    EOF
    key = OpenSSL::PKey::RSA.new(pem, "abcdef")
    assert_same_rsa rsa1024, key
    key = OpenSSL::PKey::RSA.new(pem) { "abcdef" }
    assert_same_rsa rsa1024, key

    cipher = OpenSSL::Cipher.new("aes-128-cbc")
    exported = rsa1024.to_pem(cipher, "abcdef\0\1")
    assert_same_rsa rsa1024, OpenSSL::PKey::RSA.new(exported, "abcdef\0\1")
    assert_raise(OpenSSL::PKey::RSAError) {
      OpenSSL::PKey::RSA.new(exported, "abcdef")
    }
  end

  def test_RSAPublicKey
    rsa1024 = Fixtures.pkey("rsa1024")
    asn1 = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(rsa1024.n),
      OpenSSL::ASN1::Integer(rsa1024.e)
    ])
    key = OpenSSL::PKey::RSA.new(asn1.to_der)
    assert_not_predicate key, :private?
    assert_same_rsa dup_public(rsa1024), key

    pem = <<~EOF
    -----BEGIN RSA PUBLIC KEY-----
    MIGJAoGBAMvCxLDUQKc+1P4+Q6AeFwYDvWfALb+cvzlUEadGoPE6qNWHsLFoo8RF
    geyTgE8KQTduu1OE9Zz2SMcRBDu5/1jWtsLPSVrI2ofLLBARUsWanVyki39DeB4u
    /xkP2mKGjAokPIwOI3oCthSZlzO9bj3voxTf6XngTqUX8l8URTmHAgMBAAE=
    -----END RSA PUBLIC KEY-----
    EOF
    key = OpenSSL::PKey::RSA.new(pem)
    assert_same_rsa dup_public(rsa1024), key
  end

  def test_PUBKEY
    rsa1024 = Fixtures.pkey("rsa1024")
    asn1 = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::ObjectId("rsaEncryption"),
        OpenSSL::ASN1::Null(nil)
      ]),
      OpenSSL::ASN1::BitString(
        OpenSSL::ASN1::Sequence([
          OpenSSL::ASN1::Integer(rsa1024.n),
          OpenSSL::ASN1::Integer(rsa1024.e)
        ]).to_der
      )
    ])
    key = OpenSSL::PKey::RSA.new(asn1.to_der)
    assert_not_predicate key, :private?
    assert_same_rsa dup_public(rsa1024), key

    pem = <<~EOF
    -----BEGIN PUBLIC KEY-----
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDLwsSw1ECnPtT+PkOgHhcGA71n
    wC2/nL85VBGnRqDxOqjVh7CxaKPERYHsk4BPCkE3brtThPWc9kjHEQQ7uf9Y1rbC
    z0layNqHyywQEVLFmp1cpIt/Q3geLv8ZD9pihowKJDyMDiN6ArYUmZczvW4976MU
    3+l54E6lF/JfFEU5hwIDAQAB
    -----END PUBLIC KEY-----
    EOF
    key = OpenSSL::PKey::RSA.new(pem)
    assert_same_rsa dup_public(rsa1024), key

    assert_equal asn1.to_der, dup_public(rsa1024).to_der
    assert_equal pem, dup_public(rsa1024).export
  end

  def test_pem_passwd
    key = Fixtures.pkey("rsa1024")
    pem3c = key.to_pem("aes-128-cbc", "key")
    assert_match (/ENCRYPTED/), pem3c
    assert_equal key.to_der, OpenSSL::PKey.read(pem3c, "key").to_der
    assert_equal key.to_der, OpenSSL::PKey.read(pem3c) { "key" }.to_der
    assert_raise(OpenSSL::PKey::PKeyError) {
      OpenSSL::PKey.read(pem3c) { nil }
    }
  end

  def test_private_encoding
    rsa1024 = Fixtures.pkey("rsa1024")
    asn1 = OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(0),
      OpenSSL::ASN1::Sequence([
        OpenSSL::ASN1::ObjectId("rsaEncryption"),
        OpenSSL::ASN1::Null(nil)
      ]),
      OpenSSL::ASN1::OctetString(rsa1024.to_der)
    ])
    assert_equal asn1.to_der, rsa1024.private_to_der
    assert_same_rsa rsa1024, OpenSSL::PKey.read(asn1.to_der)

    pem = <<~EOF
    -----BEGIN PRIVATE KEY-----
    MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAMvCxLDUQKc+1P4+
    Q6AeFwYDvWfALb+cvzlUEadGoPE6qNWHsLFoo8RFgeyTgE8KQTduu1OE9Zz2SMcR
    BDu5/1jWtsLPSVrI2ofLLBARUsWanVyki39DeB4u/xkP2mKGjAokPIwOI3oCthSZ
    lzO9bj3voxTf6XngTqUX8l8URTmHAgMBAAECgYEApKX8xBqvJ7XI7Kypfo/x8MVC
    3rxW+1eQ2aVKIo4a7PKGjQz5RVIVyzqTUvSZoMTbkAxlSIbO5YfJpTnl3tFcOB6y
    QMxqQPW/pl6Ni3EmRJdsRM5MsPBRZOfrXxOCdvXu1TWOS1S1TrvEr/TyL9eh2WCd
    CGzpWgdO4KHce7vs7pECQQDv6DGoG5lHnvbvj9qSJb9K5ebRJc8S+LI7Uy5JHC0j
    zsHTYPSqBXwPVQdGbgCEycnwwKzXzT2QxAQmJBQKun2ZAkEA2W3aeAE7Xi6zo2eG
    4Cx4UNMHMIdfBRS7VgoekwybGmcapqV0aBew5kHeWAmxP1WUZ/dgZh2QtM1VuiBA
    qUqkHwJBAOJLCRvi/JB8N7z82lTk2i3R8gjyOwNQJv6ilZRMyZ9vFZFHcUE27zCf
    Kb+bX03h8WPwupjMdfgpjShU+7qq8nECQQDBrmyc16QVyo40sgTgblyiysitvviy
    ovwZsZv4q5MCmvOPnPUrwGbRRb2VONUOMOKpFiBl9lIv7HU//nj7FMVLAkBjUXED
    83dA8JcKM+HlioXEAxCzZVVhN+D63QwRwkN08xAPklfqDkcqccWDaZm2hdCtaYlK
    funwYkrzI1OikQSs
    -----END PRIVATE KEY-----
    EOF
    assert_equal pem, rsa1024.private_to_pem
    assert_same_rsa rsa1024, OpenSSL::PKey.read(pem)
  end

  def test_private_encoding_encrypted
    rsa1024 = Fixtures.pkey("rsa1024")
    encoded = rsa1024.private_to_der("aes-128-cbc", "abcdef")
    asn1 = OpenSSL::ASN1.decode(encoded) # PKCS #8 EncryptedPrivateKeyInfo
    assert_kind_of OpenSSL::ASN1::Sequence, asn1
    assert_equal 2, asn1.value.size
    assert_not_equal rsa1024.private_to_der, encoded
    assert_same_rsa rsa1024, OpenSSL::PKey.read(encoded, "abcdef")
    assert_same_rsa rsa1024, OpenSSL::PKey.read(encoded) { "abcdef" }
    assert_raise(OpenSSL::PKey::PKeyError) { OpenSSL::PKey.read(encoded, "abcxyz") }

    encoded = rsa1024.private_to_pem("aes-128-cbc", "abcdef")
    assert_match (/BEGIN ENCRYPTED PRIVATE KEY/), encoded.lines[0]
    assert_same_rsa rsa1024, OpenSSL::PKey.read(encoded, "abcdef")

    # certtool --load-privkey=test/fixtures/pkey/rsa1024.pem --to-p8 --password=abcdef
    pem = <<~EOF
    -----BEGIN ENCRYPTED PRIVATE KEY-----
    MIICojAcBgoqhkiG9w0BDAEDMA4ECLqajUdSNfzwAgIEkQSCAoCDWhxr1HUrKLXA
    FsFGGQfPT0aKH4gZipaSXXQRl0KwifHwHoDtfo/mAkJVZMnUVOm1AQ4LTFS3EdTy
    JUwICGEQHb7QAiokIRoi0K2yHhOxVO8qgbnWuisWpiT6Ru1jCqTs/wcqlqF7z2jM
    oXDk/vuekKst1DDXDcHrzhDkwhCQWj6jt1r2Vwaryy0FyeqsWAgBDiK2LsnCgkGD
    21uhNZ/iWMG6tvY9hB8MDdiBJ41YdSG/AKLulAxQ1ibJz0Tasu66TmwFvWhBlME+
    QbqfgmkgWg5buu53SvDfCA47zXihclbtdfW+U3CJ9OJkx0535TVdZbuC1QgKXvG7
    4iKGFRMWYJqZvZM3GL4xbC75AxjXZsdCfV81VjZxjeU6ung/NRzCuCUcmBOQzo1D
    Vv6COwAa6ttQWM0Ti8oIQHdu5Qi+nuOEHDLxCxD962M37H99sEO5cESjmrGVxhEo
    373L4+11geGSCajdp0yiAGnXQfwaKta8cL693bRObN+b1Y+vqtDKH26N9a4R3qgg
    2XwgQ5GH5CODoXZpi0wxncXO+3YuuhGeArtzKSXLNxHzIMlY7wZX+0e9UU03zfV/
    aOe4/q5DpkNxgHePt0oEpamSKY5W3jzVi1dlFWsRjud1p/Grt2zjSWTYClBlJqG1
    A/3IeDZCu+acaePJjFyv5dFffIj2l4bAYB+LFrZlSu3F/EimO/dCDWJ9JGlMK0aF
    l9brh7786Mo+YfyklaqMMEHBbbR2Es7PR6Gt7lrcIXmzy9XSsxT6IiD1rG9KKR3i
    CQxTup6JAx9w1q+adL+Ypikoy3gGD/ccUY6TtPoCmkQwSCS+JqQnFlCiThDJbu+V
    eqqUNkZq
    -----END ENCRYPTED PRIVATE KEY-----
    EOF
    assert_same_rsa rsa1024, OpenSSL::PKey.read(pem, "abcdef")
  end

  def test_public_encoding
    rsa1024 = Fixtures.pkey("rsa1024")
    assert_equal dup_public(rsa1024).to_der, rsa1024.public_to_der
    assert_equal dup_public(rsa1024).to_pem, rsa1024.public_to_pem
  end

  def test_dup
    key = Fixtures.pkey("rsa1024")
    key2 = key.dup
    assert_equal key.params, key2.params
    key2.set_key(key2.n, 3, key2.d)
    assert_not_equal key.params, key2.params
  end

  def test_marshal
    key = Fixtures.pkey("rsa2048")
    deserialized = Marshal.load(Marshal.dump(key))

    assert_equal key.to_der, deserialized.to_der
  end

  private
  def assert_same_rsa(expected, key)
    check_component(expected, key, [:n, :e, :d, :p, :q, :dmp1, :dmq1, :iqmp])
  end
end

end
