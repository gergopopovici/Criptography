import os
import json
from blockCoder import AESProccessor, VigenereProcessor, read_gif, write_gif

def encrypt_data(data, config):
    if config['Algorithm'] == 'AES':
        processor = AESProccessor(config)
    elif config['Algorithm'] == 'Vigenere':
        processor = VigenereProcessor(config)
    else:
        raise ValueError("Invalid algorithm")
    return processor.encrypt(data)

def decrypt_data(data, config):
    if config['Algorithm'] == 'AES':
        processor = AESProccessor(config)
    elif config['Algorithm'] == 'Vigenere':
        processor = VigenereProcessor(config)
    else:
        raise ValueError("Invalid algorithm")
    return processor.decrypt(data)

def read_in_config(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def test():
    config1 = read_in_config('./json/input1.json')
    config2 = read_in_config('./json/input2.json')
    config3 = read_in_config('./json/input3.json')
    config4 = read_in_config('./json/input4.json')
    config5 = read_in_config('./json/input5.json')
    config6 = read_in_config('./json/input6.json')
    config7 = read_in_config('./json/input7.json')
    config8 = read_in_config('./json/input8.json')
    config9 = read_in_config('./json/input9.json')
    config10 = read_in_config('./json/input10.json')
    data1 = read_gif('./input/input.gif')

    output_folder = "output"
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    encrypted1 = encrypt_data(data1, config1)
    decrypted1 = decrypt_data(encrypted1, config1)
    write_gif('./output/output1.gif', decrypted1)

    encrypted2 = encrypt_data(data1, config2)
    decrypted2 = decrypt_data(encrypted2, config2)
    write_gif('./output/output2.gif', decrypted2)

    encrypted3 = encrypt_data(data1, config3)
    decrypted3 = decrypt_data(encrypted3, config3)
    write_gif('./output/output3.gif', decrypted3)

    encrypted4 = encrypt_data(data1, config4)
    decrypted4 = decrypt_data(encrypted4, config4)
    write_gif('./output/output4.gif', decrypted4)

    encrypted5 = encrypt_data(data1, config5)
    decrypted5 = decrypt_data(encrypted5, config5)
    write_gif('./output/output5.gif', decrypted5)

    encrypted6 = encrypt_data(data1, config6)
    decrypted6 = decrypt_data(encrypted6, config6)
    write_gif('./output/output6.gif', decrypted6)

    encrypted7 = encrypt_data(data1, config7)
    decrypted7 = decrypt_data(encrypted7, config7)
    write_gif('./output/output7.gif', decrypted7)

    encrypted8 = encrypt_data(data1, config8)
    decrypted8 = decrypt_data(encrypted8, config8)
    write_gif('./output/output8.gif', decrypted8)

    encrypted9 = encrypt_data(data1, config9)
    decrypted9 = decrypt_data(encrypted9, config9)
    write_gif('./output/output9.gif', decrypted9)

    encrypted10 = encrypt_data(data1, config10)
    decrypted10 = decrypt_data(encrypted10, config10)
    write_gif('./output/output10.gif', decrypted10)

def main():
    test()

if __name__ == '__main__':
    main()