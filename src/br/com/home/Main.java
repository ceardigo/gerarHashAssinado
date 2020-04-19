package br.com.home;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Main {

    public static void main(String[] args)
            throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException {

        // Geração da chave privada e pública.
        // Deverá ser feito apenas uma vez pelo BPM, que irá armazenar a chave privada e exportar a chave pública
        KeyPair parChaves = Main.gerarChave();

        // Exportação da chave pública para Base64.
        // BPM deve fazer e enviar o resultado para que seja importado na ICP
        String chavePublicaBase64 = Base64.getEncoder().encodeToString(parChaves.getPublic().getEncoded());

        // Texto que será assinado, será a concatenação do nonce, body, url e etc.
        String textoParaAssinar = "<nonce, body, url....>";

        // Gerar um hash e assinar com a chave privada, será feito apenas no BPM
        // O resultado deverá estar em Base64 e será enviado em algum campo (header x-signature?)
        String hashAssinadoBase64 = Main.gerarHashAssinado(textoParaAssinar, parChaves.getPrivate());

        // Verificar se assinatura está válida, será feito apenas na ICP
        boolean assinaturaValida = Main.verificarAssinatura(textoParaAssinar, chavePublicaBase64, hashAssinadoBase64);
        System.out.println("Assinatura dválida? " + assinaturaValida);

    }

    private static KeyPair gerarChave() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private static String gerarHashAssinado(String text, PrivateKey chavePrivada)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // Assinar o hash com a chave privada e fazer o encode para base64
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(chavePrivada);
        privateSignature.update(text.getBytes());
        return Base64.getEncoder().encodeToString(privateSignature.sign());
    }

    private static boolean verificarAssinatura(String text, String chavePublicaBase64, String hashAssinado)
            throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, SignatureException {

        // Obter objeto PublicKey
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PublicKey pub = factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(chavePublicaBase64)));

        // Verificar se assinatura é válida
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(pub);
        publicSignature.update(text.getBytes());
        return publicSignature.verify(Base64.getDecoder().decode(hashAssinado));

    }
}
