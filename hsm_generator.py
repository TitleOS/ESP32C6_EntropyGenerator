import serial
import hashlib
import sys
import argparse
import logging
import time
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Configure persistent logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        #logging.FileHandler("hsm_generator.log"), #Disabled for security
        logging.StreamHandler(sys.stdout)
    ]
)

class HardwareEntropyService:
    def __init__(self, port: str, baudrate: int = 115200, timeout: int = 2):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.connection = None

    def connect(self):
        try:
            self.connection = serial.Serial(self.port, self.baudrate, timeout=self.timeout)
            # Flush any stale data that pooled before the script started
            self.connection.reset_input_buffer()
            logging.info(f"Successfully connected to HSM on {self.port}")
        except serial.SerialException as e:
            logging.error(f"CRITICAL: Failed to connect to HSM on {self.port}. Error: {e}")
            sys.exit(1)

    def health_check(self) -> bool:
        """Verifies the serial connection is open and readable."""
        return self.connection is not None and self.connection.is_open
        
    def rand_func(self, n_bytes: int) -> bytes:
        """
        Blocks and reads raw integers from the ESP32-C6 over serial.
        Compresses the ASCII strings into a uniformly distributed byte stream via SHA-256.
        """
        if not self.health_check():
            raise RuntimeError("Serial connection is not active.")

        pool = b""
        while len(pool) < n_bytes:
            try:
                line = self.connection.readline().strip()
                if not line:
                    continue
                
                # Compress the raw numeric string into secure bytes
                hasher = hashlib.sha256()
                hasher.update(line)
                pool += hasher.digest()
                
            except serial.SerialException as e:
                logging.error(f"Error reading from serial: {e}")
                sys.exit(1)
                
        # Truncate to the exact length requested by the crypto algorithm
        return pool[:n_bytes]

    def close(self):
        if self.connection and self.connection.is_open:
            self.connection.close()
            logging.info("Serial connection closed.")

def main():
    parser = argparse.ArgumentParser(description="Generate cryptographic keys using ESP32-C6 hardware entropy.")
    parser.add_argument("--type", choices=['aes', 'rsa', 'both'], required=True, 
                        help="The type of key to generate (aes, rsa, or both).")
    parser.add_argument("--outdir", type=Path, required=True, 
                        help="Directory path where the keys will be saved.")
    parser.add_argument("--port", type=str, default="/dev/ttyACM0", 
                        help="Serial port for the ESP32-C6 (e.g., /dev/ttyACM0 or COM3)")
    
    args = parser.parse_args()

    # Ensure the target directory actually exists before trying to write files
    args.outdir.mkdir(parents=True, exist_ok=True)

    hsm = HardwareEntropyService(args.port)
    hsm.connect()
    
    if args.type in ['aes', 'both']:
        logging.info("Gathering hardware entropy for AES-256 key...")
        
        start_time = time.time()
        # AES-256 strictly requires 32 bytes (256 bits)
        aes_raw = hsm.rand_func(32)
        aes_hex = aes_raw.hex()
        
        aes_path = args.outdir / "aes_256.key"
        with open(aes_path, 'w') as f:
            f.write(aes_hex)
            
        elapsed = time.time() - start_time
        logging.info(f"AES-256 key saved successfully to {aes_path} (Took {elapsed:.2f} seconds)")
        
    if args.type in ['rsa', 'both']:
        logging.info("Gathering extensive entropy pool for RSA-4096 generation...")
        logging.info("(This takes a moment as it streams thousands of bytes to hunt for large primes)")
        
        start_time = time.time()
        # We map our custom hardware function directly into the RSA generator
        rsa_key = RSA.generate(4096, randfunc=hsm.rand_func)
        
        private_pem = rsa_key.export_key().decode('utf-8')
        public_pem = rsa_key.publickey().export_key().decode('utf-8')
        
        priv_path = args.outdir / "rsa_4096_priv.pem"
        pub_path = args.outdir / "rsa_4096_pub.pem"
        
        with open(priv_path, 'w') as f:
            f.write(private_pem)
        with open(pub_path, 'w') as f:
            f.write(public_pem)
            
        elapsed = time.time() - start_time
        logging.info(f"RSA-4096 private key saved successfully to {priv_path}")
        logging.info(f"RSA-4096 public key saved successfully to {pub_path}")
        logging.info(f"RSA-4096 generation and saving completed in {elapsed:.2f} seconds")
    
    hsm.close()

if __name__ == "__main__":
    main()