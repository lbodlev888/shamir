from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime
import json
from secrets import token_bytes
from base64 import b64encode as b64e, b64decode as b64d
from math import log2

class Shamir:
    "simple Shamir's Secret Sharing implementation"
    def __init__(self, secret: bytes | None = None, n: int | None = None, k: int | None = None) -> None:
        "inits a Shamir instance. secret is data to be shared, n - total number of shares, k - minimum number of shares to recover the secret"
        if k and n and k > n:
            raise ValueError("k > n secret irrecoverable")
        self.__coefficients = []
        self.__shares = []
        if secret != None:
            self.__secret = bytes_to_long(secret)
            self.__coefficients.append(self.__secret)
            primeLen = int(log2(self.__secret)) + 5
            self.__p = getPrime(primeLen)
            self.__n = n if n else 0
            self.__k = k if k else 0
            self.__generate_coefs()
            self.__generate_shares()

    def __generate_coefs(self) -> None:
        "IGNORE(internal only). Generates coefficients for the polynomial function, before generating shares."
        for _ in range(self.__k-1):
            temp_coef = bytes_to_long(token_bytes(20)) % self.__p
            self.__coefficients.append(temp_coef)

    def recover(self) -> bytes:
        "this method recovers the shared secret in bytes form"
        result = 0
        for j in range(self.__k):
            product = 1
            for m in range(self.__k):
                if m == j:
                    continue
                inv_denom = pow(self.__shares[m][0] - self.__shares[j][0], -1, self.__p)
                product *= (self.__shares[m][0] * inv_denom) % self.__p
            result += (self.__shares[j][1] * product) % self.__p
            result %= self.__p
        return long_to_bytes(result)

    def __generate_random_point(self) -> tuple:
        "IGNORE(internal only). This function is the one that generates plain share aka coordinate"
        x = bytes_to_long(token_bytes(20)) % self.__p
        y = 0
        for i, coef in enumerate(self.__coefficients):
            y = (y + coef * pow(x, i, self.__p)) % self.__p
        return (x, y)

    def get_public(self) -> dict:
        "Exports public data like prime, nr of shares and the threshold in dict/json format"
        return {'p': self.__p, 'k': self.__k}

    def set_public(self, public_data: dict) -> None:
        "This method sets public data like the finite field(prime p) and threshold k. Alternativ to loading it from a json file using load_public method. Finite field should use key p and threshold key k"
        if 'p' in public_data:
            self.__p = public_data['p']
        else:
            raise ValueError('missing finite field')
        if 'k' in public_data:
            self.__k = public_data['k']
        else:
            raise ValueError('missing threshold')

    def export_public(self, filename: str) -> None:
        "exports public data in a json format. data like prime number, total number of shares and minimum number of shares to reconstruct the secret aka threshold. Required at reconstruction"
        data = {'p': self.__p, 'k': self.__k}
        with open(filename, 'w') as f:
            json.dump(data, f)

    def load_shares(self, template: str, indexes: list) -> None:
        "used at reconstruction. Pass the same template used at exporting_shares, also pass a list of indexes, the ones to inject when reconstructing and the ones you have. Even if you have more then threshold all will be loaded but used no more then threshold"
        for index in indexes:
            with open(template.format(index), 'r') as f:
                share = self.__raw_share_to_usable_data(f.read())
                self.__shares.append(share)

    def __raw_share_to_usable_data(self, source: str) -> tuple:
        "INTERNAL USE. This function only share from base64 into tuple of x and y"
        return tuple(int(coord) for coord in b64d(source.encode()).decode().split(';'))

    def export_shares(self, template: str) -> None:
        "exports the all n shares following the template. Template example: share{}.txt. Function will use format to inject id in your template"
        for i, share in enumerate(self.__shares):
            with open(template.format(i+1), 'w') as f:
                f.write(share)

    def get_shares(self) -> list:
        "This function returns the shares as a list without exporting them"
        return self.__shares

    def set_shares(self, shares: list) -> None:
        for share in shares:
            share = self.__raw_share_to_usable_data(share)
            self.__shares.append(share)

    def load_public(self, filename: str) -> None:
        "loads public json file, json exported with export_public method"
        with open(filename, 'r') as f:
            data = json.load(f)
        self.__n = data['n']
        self.__k = data['k']
        self.__p = data['p']
        if self.__k > self.__n:
            raise ValueError("k > n secret irrecoverable")

    def __generate_shares(self) -> None:
        "IGNORE(internal only). This function is the one that generates all the shares and cummulates them in one array"
        for _ in range(1, self.__n+1):
            point = self.__generate_random_point()
            share = ';'.join(str(coordinate) for coordinate in point)
            share = b64e(share.encode()).decode()
            self.__shares.append(share)

if __name__ == '__main__':
    shamir = Shamir(b'top secret data', n=10, k=9)
    public = shamir.get_public()
    shares = shamir.get_shares()
    
    shamir1 = Shamir()
    shamir1.set_public(public)
    shamir1.set_shares(shares) # not practical cause here all 10 shares are used when only 4 are needed
    print(shamir1.recover())
