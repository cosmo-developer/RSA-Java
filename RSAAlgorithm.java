import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

/**
 *
 * @author Sonu Aryan <cosmo-developer@github.com>
 */
public class RSAAlgorithm {

    public static final int KEY_SIZE = 1024;
    static final BigInteger BASE_2 = BigInteger.valueOf(2l);
    static final BigInteger MIN_LIMIT = BASE_2.pow(KEY_SIZE-1);
    static final BigInteger MAX_LIMIT = BASE_2.pow(KEY_SIZE);

    public static BigInteger RandomBig() {
        BigInteger bigInteger = MAX_LIMIT.subtract(MIN_LIMIT);
        Random randNum = new Random();
        int len = MAX_LIMIT.bitLength();
        BigInteger res = new BigInteger(len, randNum);
        if (res.compareTo(MIN_LIMIT) < 0) {
            res = res.add(MIN_LIMIT);
        }
        if (res.compareTo(bigInteger) >= 0) {
            res = res.mod(bigInteger).add(MIN_LIMIT);
        }
        return res;
    }

    public static void main(String[] args) {
        BigInteger plainText = new BigInteger("sonu".getBytes());

        SecureRandom random = new SecureRandom();
        BigInteger p1 = BigInteger.probablePrime(KEY_SIZE, random);
        BigInteger p2 = BigInteger.probablePrime(KEY_SIZE, random);
        BigInteger phi = p1.subtract(BigInteger.ONE).multiply(p2.subtract(BigInteger.ONE));
        BigInteger N = p1.multiply(p2);
        
        BigInteger e=null;
        while(true){
            e=RandomBig();
            if (e.gcd(phi).equals(BigInteger.ONE)){
                break;
            }
        }
        BigInteger d=e.modInverse(phi);
        
        BigInteger cipherText=plainText.modPow(e, N);
        System.out.println("Original Message:"+plainText);
        System.out.println("Encrypted Message:"+cipherText);
        BigInteger decrypt=cipherText.modPow(d, N);
        System.out.println("Decrypted Message:"+decrypt);
        
    }
}
