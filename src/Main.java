import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.Scanner;

/**
 * @author Alberto Gutiérrez Morán
 */

public class Main {
    public static int MOD = 0;

    public static void main(String[] args) throws FileNotFoundException {
        //CIFRAMOS EL ALFABETO
        String alf = "abcdefghijklmnñopqrstuvwxyzABCDEFGHIJKLMNÑOPQRSTUVWXYZáéíóúÁÉÍÓÚ0123456789 ,.:!-¿?()";
        ArrayList<Alfabeto> alfabeto = new ArrayList<>();
        MOD = alf.length();
        for(int i=0; i<alf.length(); i++){
            Alfabeto nuevo = new Alfabeto(alf.charAt(i), i);
            alfabeto.add(nuevo);
        }

        //DESCIFRADO DE PAR (K*,C) ----------------------------

        //CLAVE PUBLICA DEL RECEPTOR => 0 = n / 1 = e / 2 = factorizacion de n numero 1 / 3 = fact. de n numero 2
        //OBTENER FACTORIZACION EN MAXIMA: ifactors(numeron);
        BigInteger factorizacion[] =  new BigInteger[]{new BigInteger("148193"),new BigInteger("148199")};
        BigInteger clave[] = new BigInteger[]{new BigInteger("21962054407"),new BigInteger("80263681"),factorizacion[0],factorizacion[1]};

        //TAMAÑO DE BLOQUE DE CIFRADO => K
        int k = getK(clave[0]);

        //DESCODIFICAMOS EL PAR K*,C
        String kCod = "dÑ(.ZQe qCurdEÑKÍHfk!QEedoÓM1F";
        String msgCifrado = "yáxFMm dTlqGM!Emi9Q)7h¿iÚYymrvLúfYLÉvxnf68U0WWfÓ)p)wzRqGLú)UtÚcoQdgL l fi?(FFxEHLUz:jx7scoFÑD::mOZK?3Mf.THFUOat3ogaÉI?U0ÁPA6tyg7girF,FDÉíYkLzRú4:PPw),E!WBQT:SWí:,túVÍ:JM7ÓQn:XúLíÍ,uS1gXmNao0eKzÓjÁ:x3OmóI09AnkA:?ÑIDg17(AXoXFGHc6(q75rWO!";

        //GENERAMOS LA CLAVE EXTENDIDA
        String Kstring = decodificarMSG(kCod,k,clave,alfabeto);     //DESCIFRAMOS K CON RSA
        int kDesc[] = getClaveExtendida(alfabeto,Kstring,msgCifrado.length());  //EXTENDEMOS K HASTA LA LON. DEL MSG CIFRADO//CON VIGENERE

        //OBTENEMOS EL MENSAJE EN CLARO
        String msgClaro = getMensajeClaro(alfabeto, kDesc, msgCifrado);     //OBTENEMOS EL MSG EN CLARO CON VIGENERE
        System.out.println(msgClaro);

        //FIN DESCIFRADO DE PAR (K*,C) --------------------------------
        System.out.println("------------------------------");
        //CIFRADO DE PAR (CODIGO, MENSAJE) ----------------------------

        //CLAVE PUBLICA DEL RECEPTOR
        BigInteger factorizacion2[] =  new BigInteger[]{new BigInteger("98179"),new BigInteger("98207")};
        BigInteger clave2[] = new BigInteger[]{new BigInteger("9641865053"),new BigInteger("70241161"),factorizacion[0],factorizacion[1]};

        //CIFRAMOS EL CODIGO (CON RSA) Y LA CLAVE (CON VIGENERE)
        String k2 = "MARTE";
        String k2Cifrada = codificarMSG(k2,k,clave,alfabeto);
        String msg2 = "GACELA DE LA TERRIBLE PRESENCIA (Federico García Lorca, 1898-1936)";
        int k2ext[] = getClaveExtendida(alfabeto,k2,msg2.length());
        String msg2Cifrado = getMensajeCod(alfabeto,k2ext,msg2);

        System.out.println("CODIGO CIFRADO: "+k2Cifrada);
        System.out.println("MENSAJE CIFRADO: "+msg2Cifrado);
        //FIN CIFRADO DE PAR (CODIGO, MENSAJE) ----------------------------
    }

    private static String getMensajeClaro(ArrayList<Alfabeto> list, int k[], String msgCifrado){
        int msgCif[] = new int[msgCifrado.length()];
        int msgCla[] = new int[msgCifrado.length()];
        String msgClaro = "";

        for(int i=0; i<msgCifrado.length(); i++){
            msgCif[i] = getPos(msgCifrado.charAt(i),list);
            msgCla[i] = modulo((msgCif[i]-k[i]),MOD);
            char add = getChar(msgCla[i],list);
            if(add==' ' && msgCla[i]==msgCla[i-1]) add='\n';    //AÑADIMOS SALTO DE LÍNEA SI HAY DOS ESPACIOS SEGUIDOS
            msgClaro+=add;
        }

        return msgClaro;
    }

    private static String getMensajeCod(ArrayList<Alfabeto> list, int k[], String msgCifrado){
        int msgCif[] = new int[msgCifrado.length()];
        int msgCla[] = new int[msgCifrado.length()];
        String msgClaro = "";

        for(int i=0; i<msgCifrado.length(); i++){
            msgCif[i] = getPos(msgCifrado.charAt(i),list);
            msgCla[i] = modulo((msgCif[i]+k[i]),MOD);
            char add = getChar(msgCla[i],list);
            msgClaro+=add;
        }

        return msgClaro;
    }

    private static String codificarMSG(String msg, int k, BigInteger[] clave, ArrayList<Alfabeto> alf){
        BigInteger mod = BigInteger.valueOf(MOD);
        int grupos = msg.length()/k;
        String out = "";

        for(int i=0; i<(grupos*k); i+=k){
            //0. OBTENEMOS EL BLOQUE A CODIFICAR
            String bloque = msg.substring(i,(i+k));
            //1. PASAMOS DE BLOQUE A ENTERO
            int[] codNumerica = new int[k];
            for(int j=0; j<k; j++){codNumerica[j]=getPos(bloque.charAt(j),alf);}
            BigInteger entero = BigInteger.valueOf(0);
            for(int j=0; j<k; j++){
                entero=entero.add(BigInteger.valueOf(codNumerica[j]).multiply(mod.pow(k-j-1)));
            }
            //2. CIFRAMOS CON RSA SIMPLE
            BigInteger cifrado = entero.modPow(clave[1],clave[0]); //entero^e en modulo n
            //3. PASAR DE ENTERO A BLOQUE
            int[] bloquecifradoNum = enteroaBloque(cifrado,k+1);
            String bloquecifrado = "";
            for(int j=0; j<=k; j++){
                bloquecifrado += getChar(bloquecifradoNum[j],alf);
            }
            out+=bloquecifrado;
        }

        return out;
    }

    private static int[] getClaveExtendida(ArrayList<Alfabeto> alfabeto, String Kstring, int len){
        int k[] = new int[len];
        for(int i=0; i<Kstring.length(); i++){
            k[i] = getPos(Kstring.charAt(i),alfabeto);
        }

        int funcion[] = k;
        for(int i=Kstring.length(); i<len; i++){
            int valor = 0;
            for(int x=0; x<Kstring.length(); x++){
                valor+=funcion[x]*k[i-(x+1)]; //k=[1,4] => valor=1*[k-1] + 4*[k-2]
            }
            k[i] = modulo(valor,MOD);
        }

        return k;
    }

    private static String decodificarMSG(String msg, int k, BigInteger[] clave, ArrayList<Alfabeto> alf){
        BigInteger mod = BigInteger.valueOf(MOD);
        int tam = k+1;
        int grupos = msg.length()/tam;
        String out = "";

        for(int i=0; i<(grupos*tam); i+=tam){
            //1. OBTENEMOS EL BLOQUE A DESCIFRAR
            String bloque = msg.substring(i,(i+tam));
            //2. PASAMOS DE BLOQUE A ENTERO
            int[] codNumerica = new int[tam];
            for(int j=0; j<tam; j++){codNumerica[j]=getPos(bloque.charAt(j),alf);}
            BigInteger entero = BigInteger.valueOf(0);
            for(int j=0; j<tam; j++){
                entero=entero.add(BigInteger.valueOf(codNumerica[j]).multiply(mod.pow(tam-j-1)));
            }
            //3. DESCIFRAMOS EL ENTERO USANDO RSA SIMPLE
            BigInteger newmodulo = (clave[2].subtract(BigInteger.ONE)).multiply(clave[3].subtract(BigInteger.ONE)); //(p-1) * (q-1)
            BigInteger inverso = clave[1].modInverse(newmodulo);    //inverso de e en newmodulo
            BigInteger enteroClaro = entero.modPow(inverso,clave[0]);   // entero^inverso en modulo n
            //4. PASAR EL ENTERO EN CLARO A BLOQUE
            int[] bloquecifradoNum = enteroaBloque(enteroClaro,k);
            String bloquecifrado = "";
            for(int j=0; j<k; j++){
                bloquecifrado += getChar(bloquecifradoNum[j],alf);
            }
            out+=bloquecifrado;
        }

        //SI HAY DOS ESPACIOS SEGUIDOS AÑADIMOS UN SALTO DE LÍNEA
        for(int i=1; i<out.length()-2; i++){
            if(out.charAt(i)==' ' && out.charAt(i-1)==' '){
                out = out.substring(0,i)+'\n'+out.substring(i+1);
            }
        }
        return out;
    }

    private static int getK(BigInteger n){
        BigInteger mod = BigInteger.valueOf(MOD);
        int k = 0;
        BigInteger menor = mod.pow(k); BigInteger mayor = mod.pow(k+1);

        while(menor.compareTo(n)>0 || mayor.compareTo(n)!=1){
            k++;
            menor = mod.pow(k);
            mayor = mod.pow(k+1);
        }

        return k;
    }

    private static int[] enteroaBloque(BigInteger num, int k){
        BigInteger mod = BigInteger.valueOf(MOD);
        int[] bloque = new int[k];
        int pos = k-1;

        while(num.compareTo(BigInteger.ZERO)>0){
            bloque[pos] = num.remainder(mod).intValue();
            pos--;
            num = num.divide(mod);
        }

        for(int i=pos; i>=0; i--){
            bloque[pos] = 0;
        }

        return bloque;
    }

    private static int getPos(char c, ArrayList<Alfabeto> list){
        for(int i=0; i<list.size(); i++){
            if(c==list.get(i).getChar()){
                return list.get(i).getPos();
            }
        }
        return -1;
    }

    private static char getChar(int pos, ArrayList<Alfabeto> list){
        for(int i=0; i<list.size(); i++){
            if(pos==list.get(i).getPos()){
                return list.get(i).getChar();
            }
        }
        return ' ';
    }

    private static int modulo(int x, int mod){
        if(x<0){
            x=-1*x;
            return mod-(x-(mod * (x/mod)));
        }
        return x%mod;
    }

}
