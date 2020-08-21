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

    # :call-seq:
    #    dh.generate_key! -> self
    #
    # Generates a private and public key unless a private key already exists.
    # If this DH instance was generated from public DH parameters (e.g. by
    # encoding the result of DH#public_key), then this method needs to be
    # called first in order to generate the per-session keys before performing
    # the actual key exchange.
    #
    # See also OpenSSL::PKey.generate_key.
    #
    # Example:
    #   dh = OpenSSL::PKey::DH.new(2048)
    #   public_key = dh.public_key #contains no private/public key yet
    #   public_key.generate_key!
    #   puts public_key.private? # => true
    def generate_key!
      unless priv_key
        tmp = OpenSSL::PKey.generate_key(self)
        set_key(tmp.pub_key, tmp.priv_key)
      end
      self
    end

    class << self
      # :call-seq:
      #    DH.generate(size [, generator = 2]) -> dh
      #
      # Creates a new DH instance from scratch by generating the private and
      # public components alike.
      #
      # See also OpenSSL::PKey.generate_parameters and
      # OpenSSL::PKey.generate_key.
      #
      # size::
      #   An Integer representing the desired key size.
      # generator::
      #   A small Integer > 1, typically 2 or 5.
      def generate(size, generator = 2, &blk)
        dhparams = OpenSSL::PKey.generate_parameters("DH", {
          "dh_paramgen_prime_len" => size,
          "dh_paramgen_generator" => generator,
        }, &blk)
        OpenSSL::PKey.generate_key(dhparams)
      end

      # Handle DH.new(size, generator) form here; new(str) and new() forms
      # are handled by #initialize
      def new(*args, &blk) # :nodoc:
        if args[0].is_a?(Integer)
          generate(*args, &blk)
        else
          super
        end
      end
    end
  end

  class DSA
    include OpenSSL::Marshal

    # :call-seq:
    #    dsa.syssign(string) -> string
    #
    # Computes and returns the DSA signature of _string_, where _string_ is
    # expected to be an already-computed message digest of the original input
    # data. The signature is issued using the private key of this DSA instance.
    #
    # Deprecated in version 3.0. Consider using OpenSSL::PKey::PKey#sign_raw
    # and OpenSSL::PKey::PKey#verify_raw instead.
    #
    # string::
    #   A message digest of the original input data to be signed.
    #
    # Example:
    #   dsa = OpenSSL::PKey::DSA.new(2048)
    #   doc = "Sign me"
    #   digest = OpenSSL::Digest.digest('SHA1', doc)
    #
    #   # With legacy #syssign and #sysverify:
    #   sig = dsa.syssign(digest)
    #   p dsa.sysverify(digest, sig) #=> true
    #
    #   # With #sign_raw and #verify_raw:
    #   sig = dsa.sign_raw(nil, digest)
    #   p dsa.verify_raw(nil, sig, digest) #=> true
    def syssign(string)
      q or raise OpenSSL::PKey::DSAError, "incomplete DSA"
      private? or raise OpenSSL::PKey::DSAError, "Private DSA key needed!"
      begin
        sign_raw(nil, string)
      rescue OpenSSL::PKey::PKeyError
        raise OpenSSL::PKey::DSAError, $!.message
      end
    end

    # :call-seq:
    #    dsa.sysverify(digest, sig) -> true | false
    #
    # Verifies whether the signature is valid given the message digest input.
    # It does so by validating _sig_ using the public key of this DSA instance.
    #
    # Deprecated in version 3.0. Consider using OpenSSL::PKey::PKey#sign_raw
    # and OpenSSL::PKey::PKey#verify_raw instead.
    #
    # digest::
    #   A message digest of the original input data to be signed.
    # sig::
    #   A DSA signature value.
    def sysverify(digest, sig)
      verify_raw(nil, sig, digest)
    rescue OpenSSL::PKey::PKeyError
      raise OpenSSL::PKey::DSAError, $!.message
    end

    class << self
      # :call-seq:
      #    DSA.generate(size) -> dsa
      #
      # Creates a new DSA instance by generating a private/public key pair
      # from scratch.
      #
      # See also OpenSSL::PKey.generate_parameters and
      # OpenSSL::PKey.generate_key.
      #
      # size::
      #   An integer representing the desired key size.
      def generate(size, &blk)
        dsaparams = OpenSSL::PKey.generate_parameters("DSA", {
          "dsa_paramgen_bits" => size,
        }, &blk)
        OpenSSL::PKey.generate_key(dsaparams)
      end

      # Handle DSA.new(size) form here; new(str) and new() forms
      # are handled by #initialize
      def new(*args, &blk) # :nodoc:
        if args[0].is_a?(Integer)
          generate(*args, &blk)
        else
          super
        end
      end
    end
  end

  if defined?(EC)
  class EC
    include OpenSSL::Marshal

    # :call-seq:
    #    key.dsa_sign_asn1(data) -> String
    #
    # Deprecated in version 3.0. Consider using OpenSSL::PKey::PKey#sign_raw
    # and OpenSSL::PKey::PKey#verify_raw instead.
    def dsa_sign_asn1(data)
      sign_raw(nil, data)
    rescue OpenSSL::PKey::PKeyError
      raise OpenSSL::PKey::ECError, $!.message
    end

    # :call-seq:
    #    key.dsa_verify_asn1(data, sig) -> true | false
    #
    # Deprecated in version 3.0. Consider using OpenSSL::PKey::PKey#sign_raw
    # and OpenSSL::PKey::PKey#verify_raw instead.
    def dsa_verify_asn1(data, sig)
      verify_raw(nil, sig, data)
    rescue OpenSSL::PKey::PKeyError
      raise OpenSSL::PKey::ECError, $!.message
    end

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

    class << self
      # :call-seq:
      #    RSA.generate(size)           => RSA instance
      #    RSA.generate(size, exponent) => RSA instance
      #
      # Generates an \RSA keypair.
      #
      # See also OpenSSL::PKey.generate_key.
      #
      # size::
      #   An Integer representing the desired key size.  Keys smaller than 1024
      #   should be considered insecure.
      # exponent::
      #   An odd Integer, normally 3, 17, or 65537.
      def generate(size, exp = 0x10001, &blk)
        OpenSSL::PKey.generate_key("RSA", {
          "rsa_keygen_bits" => size,
          "rsa_keygen_pubexp" => exp,
        }, &blk)
      end

      # Handle RSA.new(size, exponent) form here; new(str) and new() forms
      # are handled by #initialize
      def new(*args, &blk) # :nodoc:
        if args[0].is_a?(Integer)
          generate(*args, &blk)
        else
          super
        end
      end
    end
  end
end
