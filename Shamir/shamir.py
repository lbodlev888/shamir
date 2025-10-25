from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, isPrime
import json
from secrets import token_bytes
from base64 import b64encode as b64e, b64decode as b64d

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
            print('Generating primes...')
            self.__p, self.__q = self.__safePrime(self.__secret.bit_length()+10)
            self.__n = n if n else 0
            self.__k = k if k else 0
            print('Generating shares...')
            self.__generate_coefs()
            self.__generate_shares()
            self.__compute_generator()

    def __safePrime(self, len: int) -> tuple:
        "generates safe prime p and q such that p = 2 * q + 1"
        while True:
            q = getPrime(len)
            p = 2 * q + 1
            if isPrime(p):
                return (p, q)

    def __compute_generator(self) -> None:
        "Internal use only. generates generator g for commitments used in feldman's scheme when verifying share"
        while True:
            h = bytes_to_long(token_bytes(20))
            self.__g = pow(h, (self.__p-1)//self.__q, self.__p)
            if self.__g != 1:
                return

    def compute_commitments(self):
        "generates and returns a list of commitments used when verifying share"
        return [pow(self.__g, coef, self.__p) for coef in self.__coefficients]

    def set_commitments(self, commitments: list) -> None:
        "Sets commitments list used in verifying validity of a share using Feldman's Scheme"
        self.__commitments = commitments

    def verify_share(self, raw_share: str | None = None, filename: str | None = None) -> bool:
        "Verifies the share using Feldman's Scheme"
        if raw_share:
            share = self.__parse_share(raw_share)
        elif filename:
            with open(filename, 'r') as f:
                share = self.__parse_share(f.read())
        else:
            raise ValueError('No mode specified')
        lh = pow(self.__g, share[1], self.__p)
        rh = 1

        for i, commit in enumerate(self.__commitments):
            rh *= pow(commit, pow(share[0], i, self.__q), self.__p)
            rh %= self.__p

        if lh == rh:
            return True
        raise ValueError('Invalid share')

    def __generate_coefs(self) -> None:
        "IGNORE(internal only). Generates coefficients for the polynomial function, before generating shares."
        for _ in range(self.__k-1):
            temp_coef = bytes_to_long(token_bytes(20))
            self.__coefficients.append(temp_coef)

    def recover(self) -> bytes:
        "this method recovers the shared secret in bytes form"
        result = 0
        for j in range(self.__k):
            product = 1
            for m in range(self.__k):
                if m == j:
                    continue
                inv_denom = pow(self.__shares[m][0] - self.__shares[j][0], -1, self.__q)
                product *= (self.__shares[m][0] * inv_denom) % self.__q
            result += (self.__shares[j][1] * product) % self.__q
            result %= self.__q
        return long_to_bytes(result)

    def __generate_random_point(self) -> tuple:
        "IGNORE(internal only). This function is the one that generates plain share aka coordinate"
        x = bytes_to_long(token_bytes(20))
        y = 0
        for i, coef in enumerate(self.__coefficients):
            y = (y + coef * pow(x, i, self.__q)) % self.__q
        return (x, y)

    def get_public(self) -> dict:
        "Exports public data like prime, nr of shares and the threshold in dict/json format"
        return {'p': self.__p, 'k': self.__k, 'q': self.__q, 'g': self.__g}

    def set_public(self, public_data: dict) -> None:
        "This method sets public data like the finite field(prime p) and threshold k. Alternativ to loading it from a json file using load_public method. Finite field should use key p and threshold key k"
        fields = ['p', 'q', 'g', 'k']
        for field in fields:
            if field in public_data:
                setattr(self, f'_{Shamir.__name__}__{field}', public_data[field])

    def load_public(self, filename: str) -> None:
        "loads public json file, json exported with export_public method"
        with open(filename, 'r') as f:
            public_data = json.load(f)
        fields = ['p', 'q', 'g', 'k']
        for field in fields:
            if field in public_data:
                setattr(self, f'_{Shamir.__name__}__{field}', public_data[field])

    def export_public(self, filename: str) -> None:
        "exports public data in a json format. data like prime number, total number of shares and minimum number of shares to reconstruct the secret aka threshold. Required at reconstruction"
        public_data = {'p': self.__p, 'k': self.__k, 'q': self.__q, 'g': self.__g}
        with open(filename, 'w') as f:
            json.dump(public_data, f)

    def load_shares(self, template: str, indexes: list) -> None:
        "used at reconstruction. Pass the same template used at exporting_shares, also pass a list of indexes, the ones to inject when reconstructing and the ones you have. Even if you have more then threshold all will be loaded but used no more then threshold"
        for index in indexes:
            with open(template.format(index), 'r') as f:
                share = self.__parse_share(f.read())
                self.__shares.append(share)

    def __parse_share(self, source: str) -> tuple:
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
        "Loads the shares from a list instead of file. Parses them"
        for share in shares:
            share = self.__parse_share(share)
            self.__shares.append(share)

    def __generate_shares(self) -> None:
        "IGNORE(internal only). This function is the one that generates all the shares and cummulates them in one array"
        for _ in range(1, self.__n+1):
            point = self.__generate_random_point()
            share = ';'.join(str(coordinate) for coordinate in point)
            share = b64e(share.encode()).decode()
            self.__shares.append(share)

if __name__ == '__main__':
    shamir = Shamir(b'top secret data', n=100, k=5)
    shamir.export_public('public.json')
    shares = shamir.get_shares()
    commitments = shamir.compute_commitments()
    
    shamir1 = Shamir()
    shamir1.load_public('public.json')
    shamir1.set_commitments(commitments)
    for share in shares:
        if not shamir1.verify_share(share):
            print('invalid share')
    shamir1.set_shares(shares)
    print(shamir1.recover())
