//RSA cryptosystem and digital signature algorithm; methods of generating parameters for asymmetric cryptosystems

#include <iostream>
#include "RSA.hpp"

using namespace std;



struct SecretKey{
    BigInt q;
    BigInt p;
    BigInt d;
};


struct PublicKey{
    BigInt n;
    BigInt e;
};

struct SignMessage{
    BigInt mess;
    BigInt sign;
};


const int number_of_trial_division = 30;


string L89Generator(int sequence_size);
BigInt convertBinaryToDecimal(BigInt n);
BigInt modexp(BigInt x, BigInt y, BigInt N);
bool isPrime(BigInt number);
BigInt generatePrimeNumber(int size_seq);
BigInt reversElement(BigInt x,BigInt y);
SecretKey generateKey(int size_seq);

void generalmodule(SecretKey key_A, SecretKey secret_B);
BigInt encrypt(PublicKey open, BigInt mess);
BigInt decrypt(SecretKey secret, BigInt mess);
SignMessage sign(SecretKey secret, BigInt mess);
bool verify(PublicKey open, SignMessage mess);
SignMessage SendKey(PublicKey open, SecretKey secret);
void ReceiveKey(SignMessage mess, PublicKey open, SecretKey secret);


string L89Generator(int sequence_size){
    string L89_temp;
    long int generate_sequence_L89[sequence_size];
    generate_sequence_L89[0] = 1;
    srand(time(NULL));
    for (int i = 1; i<40; i++){
        generate_sequence_L89[i]=rand()%2;
    }

    for(int i = 89; i < sequence_size; i++){
        if ((generate_sequence_L89[i-38] + generate_sequence_L89[i-89])%2 == 0)
            generate_sequence_L89[i] = 0;
        else
            generate_sequence_L89[i] = 1;
    }

    stringstream ss;
    for(int i = 0; i < sequence_size; i++)
        ss<<generate_sequence_L89[i];
    L89_temp = ss.str();
    return L89_temp;        
                            
}


BigInt convertBinaryToDecimal(BigInt n)
{
    BigInt decimalNumber = 0, remainder, a;
    a = "2";
    int i = 0;
    while (n!=0)
    {
        remainder = n%10;
        n /= 10;
        decimalNumber += remainder*pow(a,i);
        ++i;
    }
    return decimalNumber;
}


BigInt modexp(BigInt x, BigInt y, BigInt N){
  if (y == 0) return 1;
  BigInt z = modexp(x, y / 2, N);
  if (y % 2 == 0)
    return (z*z) % N;
  else
    return (x*z*z) % N;
}


bool isPrime(BigInt number){

    int deg_2 = 0, count = 0;

    BigInt temp , number_1 = number - 1;

    temp = number_1;

    while(gcd(temp,"2") == 2){ 
        deg_2++;               
        temp = temp/2;
    }

    BigInt d_big = number_1/(pow(2,deg_2));


    for(int i = 0 ; i < number_of_trial_division ; i++){
        BigInt x_big_rand = big_random(10);

        if(gcd(x_big_rand,number) != 1)
            return false;

        if(modexp(x_big_rand, d_big, number) != 1 and modexp(x_big_rand, d_big, number) != number_1){
            BigInt r_1 = x_big_rand;

            for(int j = 1; j < deg_2; j++){
                r_1 = modexp(r_1,2,number);

                if(r_1 == 1)
                    return false;

                else if(r_1 == number_1)
                    j = deg_2;
            }
        }
        count++;
    }

    if (count == number_of_trial_division)
        return true;
}

//Choose a random prime number from the interval [p...p+100]
BigInt generatePrimeNumber(int size_seq){

    BigInt p = convertBinaryToDecimal(L89Generator(size_seq));

    if(p%2==0)
       p = p-1;
    for(int i = 0; i<100;i++){
        p = p + 2;
        cout<<p<<endl;
        if(isPrime(p) == true){
            return p;
        }
    }
    return 0;
}


BigInt reversElement(BigInt x,BigInt y){
    if(gcd(x,y) == 1){
        BigInt b0 = y, t, q;
        BigInt x0 = 0;
        BigInt x1 = 1;
        if (y == 1){
            return 1;
        }
        while (x > 1){
            q = x / y;
            t = y;
            y = x % y;
            x = t;
            t = x0;
            x0 = x1 - q * x0;
            x1 = t;
        }
        if (x1 < 0)
        {
            x1 = x1 + b0;
        }
        return x1;
    }
    else{
        return 0;
    }
}


SecretKey generateKey(int size_seq){
    SecretKey key;

    key.p = generatePrimeNumber(size_seq);
    cout<<"Prime p :"<<key.p<<endl;
    key.q = generatePrimeNumber(size_seq);
    cout<<"Prime q :"<<key.q<<endl;
    BigInt _n = (key.q - 1)*(key.p - 1);
    BigInt e;
    e = "65537";
    key.d = reversElement(e,_n);

    return key;
}



void generalmodule(SecretKey secret_A, SecretKey secret_B){
    PublicKey open_A, open_B;
    open_A.e = "65537";
    open_A.n = secret_A.p*secret_A.q;
    open_B.e = "65537";
    open_B.n = secret_B.p*secret_B.q;
    BigInt mess = encrypt(open_A);
    BigInt mess_1 = decrypt(secret_A,mess);
    SignMessage mess = sign(secret_A);
    verify(open_A,mess);
    SignMessage mess = SendKey(open_B,secret_A);
    ReceiveKey(mess,open_A,secret_B);

}


BigInt encrypt(PublicKey open, BigInt mess){

    BigInt mess = convertBinaryToDecimal(L89Generator());
    cout<<"message : "<<mess<<endl;
    BigInt enc_mess = modexp(mess,open.e,open.n);
    cout<<"encrypt massage : "<<enc_mess<<endl;
    return enc_mess;
}


BigInt decrypt(SecretKey secret, BigInt mess){
    cout<<"encrypt massage : "<<mess<<endl;
    BigInt dec_mess = modexp(mess,secret.d,secret.p*secret.q);
    cout<<"decrypt : "<<dec_mess<<endl;
    return dec_mess;
}


SignMessage sign(SecretKey secret, BigInt mess){
    SignMessage sign_mess;
    BigInt mess = convertBinaryToDecimal(L89Generator());
    sign_mess.mess = mess;
    cout<<"message : "<<mess<<endl;
    sign_mess.sign = modexp(mess,secret.d,secret.p*secret.q);
    cout<<"sign : "<<sign_mess.sign<<endl;
    return sign_mess;
}


bool verify(PublicKey open, SignMessage mess){
    BigInt sign = modexp(mess.sign, open.e, open.n);
    if(mess.mess == sign){
        cout<<"sign is verify"<<endl;
        return true;
    }
    cout<<"No"<<endl;
    return false;
}


SignMessage SendKey(PublicKey open, SecretKey secret){
    int size_k;
    BigInt k, k_1, S, S_1;
    SignMessage mess;
    cout << "k size = ";
    cin >> size_k;
    k = convertBinaryToDecimal(L89Generator(size_k));
    cout<<"secret k : "<<k<<endl;
    k_1 = modexp(k, open.e, open.n);
    cout<<"k_1 :"<<k_1<<endl;
    S = modexp(k, secret.d, secret.p*secret.q);
    cout<<"Sign S : "<<S<<endl;
    S_1 = modexp(S, open.e, open.n);
    mess.mess = k_1;
    mess.sign = S_1;
    return mess;
}


void ReceiveKey(SignMessage mess, PublicKey open, SecretKey secret){
    BigInt k, k_1, S;
    cout<<"S_1 :"<<mess.sign<<endl;
    cout<<"k_1 :"<<mess.mess<<endl;
    S = modexp(mess.sign, secret.d, secret.p*secret.q);
    k = modexp(mess.mess, secret.d, secret.p*secret.q);
    k_1 = modexp(S, open.e, open.n);
    cout<<"Sign S : "<<S<<endl;
    if(k == k_1){
        cout<<"Sign verify, k = "<<k<<endl;
    }
    else
        cout<<"NO"<<endl;
}




int main()
{

    //BigInt p_1 = generatePrimeNumber();
    //BigInt q_1 = generatePrimeNumber();
    //BigInt p_2 = generatePrimeNumber();
    //BigInt q_2 = generatePrimeNumber();

    SecretKey A;
    A.p = "333878461881536384834542388028546959989";
    A.q = "287662245803904436664744741362912873793";
    A.d = "15850807511649964997131296082700697066641709990654722527774274371862913433601";

    SecretKey B;
    B.p = "242269929646172517153063448226052728027";
    B.q = "229296464936422704525028189078431414607";
    B.d = "46320015160151828637175722185937508654593526832511001938310472922394766501321";

    //generalmodule(B, A);
    int size_seq;
    cout<<"Size k = ";
    cin>>size_seq;
    SecretKey prime_1;
    prime_1 = generateKey(size_seq);

    return 0;
}
