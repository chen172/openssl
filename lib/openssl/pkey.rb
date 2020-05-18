# frozen_string_literal: true
#--
# Ruby/OpenSSL Project
# Copyright (C) 2017 Ruby/OpenSSL Project Authors
#++

require_relative 'marshal'

module OpenSSL::PKey
  class DH
    include OpenSSL::Marshal

    # :call-seq:
    #    dh.compute_key(pub_bn) -> string
    #
    # Returns a String containing a shared secret computed from the other
    # party's public value.
    #
    # This method is provided for backwards compatibility, and calls #derive
    # internally.
    #
    # === Parameters
    # * _pub_bn_ is a OpenSSL::BN, *not* the DH instance returned by
    #   DH#public_key as that contains the DH parameters only.
    def compute_key(pub_bn)
      peer = dup
      peer.set_key(pub_bn, nil)
      derive(peer)
    end
  end

  class DSA
    include OpenSSL::Marshal
  end

  if defined?(EC)
  class EC
    include OpenSSL::Marshal

    # :call-seq:
    #    ec.dh_compute_key(pubkey) -> string
    #
    # Derives a shared secret by ECDH. _pubkey_ must be an instance of
    # OpenSSL::PKey::EC::Point and must belong to the same group.
    #
    # This method is provided for backwards compatibility, and calls #derive
    # internally.
    def dh_compute_key(pubkey)
      peer = OpenSSL::PKey::EC.new(group)
      peer.public_key = pubkey
      derive(peer)
    end
  end

  class EC::Point
    # :call-seq:
    #    point.to_bn([conversion_form]) -> OpenSSL::BN
    #
    # Returns the octet string representation of the EC point as an instance of
    # OpenSSL::BN.
    #
    # If _conversion_form_ is not given, the _point_conversion_form_ attribute
    # set to the group is used.
    #
    # See #to_octet_string for more information.
    def to_bn(conversion_form = group.point_conversion_form)
      OpenSSL::BN.new(to_octet_string(conversion_form), 2)
    end
  end
  end

  class RSA
    include OpenSSL::Marshal

    # :call-seq:
    #    rsa.private_encrypt(string)          => String
    #    rsa.private_encrypt(string, padding) => String
    #
    # Encrypt _string_ with the private key.  _padding_ defaults to
    # PKCS1_PADDING. The encrypted string output can be decrypted using
    # #public_decrypt.
    #
    # Deprecated in version 3.0. Consider using OpenSSL::PKey::PKey#sign_raw,
    # OpenSSL::PKey::PKey#verify_raw, and OpenSSL::PKey::PKey#verify_recover
    # instead.
    def private_encrypt(string, padding = PKCS1_PADDING)
      n or raise OpenSSL::PKey::RSAError, "incomplete RSA"
      private? or raise OpenSSL::PKey::RSAError, "private key needed."
      begin
        sign_raw(nil, string, {
          "rsa_padding_mode" => translate_padding_mode(padding),
        })
      rescue OpenSSL::PKey::PKeyError
        raise OpenSSL::PKey::RSAError, $!.message
      end
    end

    # :call-seq:
    #    rsa.public_decrypt(string)          => String
    #    rsa.public_decrypt(string, padding) => String
    #
    # Decrypt _string_, which has been encrypted with the private key, with the
    # public key.  _padding_ defaults to PKCS1_PADDING.
    #
    # Deprecated in version 3.0. Consider using OpenSSL::PKey::PKey#sign_raw,
    # OpenSSL::PKey::PKey#verify_raw, and OpenSSL::PKey::PKey#verify_recover
    # instead.
    def public_decrypt(string, padding = PKCS1_PADDING)
      n or raise OpenSSL::PKey::RSAError, "incomplete RSA"
      begin
        verify_recover(nil, string, {
          "rsa_padding_mode" => translate_padding_mode(padding),
        })
      rescue OpenSSL::PKey::PKeyError
        raise OpenSSL::PKey::RSAError, $!.message
      end
    end

    # :call-seq:
    #    rsa.public_encrypt(string)          => String
    #    rsa.public_encrypt(string, padding) => String
    #
    # Encrypt _string_ with the public key.  _padding_ defaults to
    # PKCS1_PADDING. The encrypted string output can be decrypted using
    # #private_decrypt.
    #
    # Deprecated in version 3.0. Consider using OpenSSL::PKey::PKey#encrypt
    # and OpenSSL::PKey::PKey#decrypt instead.
    def public_encrypt(data, padding = PKCS1_PADDING)
      n or raise OpenSSL::PKey::RSAError, "incomplete RSA"
      begin
        encrypt(data, {
          "rsa_padding_mode" => translate_padding_mode(padding),
        })
      rescue OpenSSL::PKey::PKeyError
        raise OpenSSL::PKey::RSAError, $!.message
      end
    end

    # :call-seq:
    #    rsa.private_decrypt(string)          => String
    #    rsa.private_decrypt(string, padding) => String
    #
    # Decrypt _string_, which has been encrypted with the public key, with the
    # private key. _padding_ defaults to PKCS1_PADDING.
    #
    # Deprecated in version 3.0. Consider using OpenSSL::PKey::PKey#encrypt
    # and OpenSSL::PKey::PKey#decrypt instead.
    def private_decrypt(data, padding = PKCS1_PADDING)
      n or raise OpenSSL::PKey::RSAError, "incomplete RSA"
      private? or raise OpenSSL::PKey::RSAError, "private key needed."
      begin
        decrypt(data, {
          "rsa_padding_mode" => translate_padding_mode(padding),
        })
      rescue OpenSSL::PKey::PKeyError
        raise OpenSSL::PKey::RSAError, $!.message
      end
    end

    private def translate_padding_mode(num)
      case num
      when PKCS1_PADDING
        "pkcs1"
      when PKCS1_OAEP_PADDING
        "oaep"
      when SSLV23_PADDING
        "sslv23"
      when NO_PADDING
        "none"
      else
        raise OpenSSL::PKey::PKeyError, "unsupported padding mode"
      end
    end
  end
end
