package org.example;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

public class RSA
{
    private BigInteger P;
    private BigInteger Q;
    private BigInteger N;
    private BigInteger PHI;
    private BigInteger e;
    private BigInteger d;
    private int maxLength = 1024;
    private Random R;

    public RSA()
    {
        R = new Random();
        P = BigInteger.probablePrime(maxLength, R); //вычесляем левый простой сомножитель от 1024, до R
        Q = BigInteger.probablePrime(maxLength, R); //вычесляем правый простой сомножитель от 1024, до R
        N = P.multiply(Q); //значение модуля закрытого и открытого ключей
        PHI = P.subtract(BigInteger.ONE).multiply(  Q.subtract(BigInteger.ONE)); //значение функции эйлера
        //ищем открытую экспоненту от 512 до R, ренж уменьшен, чтобы не пересечься со значением PHI
        e = BigInteger.probablePrime(maxLength / 2, R);
        //цикл старается найти наибольшее значение открытой экспоненты. Чем больше - тем лучше стойкость к подбору закрытого ключа
        while (PHI.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(PHI) < 0)
        {
            e.add(BigInteger.ONE); //просто + 1
        }
        d = e.modInverse(PHI); //модульная инверсия (d * e) % phi = 1 => d = e ^ -1 mod phi
    }

    public RSA(BigInteger e, BigInteger d, BigInteger N)
    {
        this.e = e;
        this.d = d;
        this.N = N;
    }

    public byte[] openKey(){
        return concat(e.toByteArray(), N.toByteArray());
    }

    public byte[] closeKey(){
        return concat(d.toByteArray(), N.toByteArray());
    }

    public byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
    // Encrypting the message
    public byte[] openExpKeyPow(byte[] message)
    {
        return (new BigInteger(message)).modPow(e, N).toByteArray();
    }

    // Decrypting the message
    public byte[] closeKeyExpPow(byte[] message)
    {
        return (new BigInteger(message)).modPow(d, N).toByteArray();
    }
}
