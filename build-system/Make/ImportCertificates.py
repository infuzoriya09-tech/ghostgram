import os
import sys
import argparse

from BuildEnvironment import run_executable_with_output

def import_certificates(certificatesPath):
    if not os.path.exists(certificatesPath):
        print('{} does not exist'.format(certificatesPath))
        sys.exit(1)

    keychain_name = 'temp.keychain'
    keychain_password = 'secret'

    existing_keychains = run_executable_with_output('security', arguments=['list-keychains'], check_result=True)
    if keychain_name in existing_keychains:
        run_executable_with_output('security', arguments=['delete-keychain'], check_result=True)

    run_executable_with_output('security', arguments=[
        'create-keychain',
        '-p',
        keychain_password,
        keychain_name
    ], check_result=True)

    existing_keychains = run_executable_with_output('security', arguments=['list-keychains', '-d', 'user'])
    existing_keychains.replace('"', '')

    run_executable_with_output('security', arguments=[
        'list-keychains',
        '-d',
        'user',
        '-s',
        keychain_name,
        existing_keychains
    ], check_result=True)

    run_executable_with_output('security', arguments=['set-keychain-settings', keychain_name])
    run_executable_with_output('security', arguments=['unlock-keychain', '-p', keychain_password, keychain_name])

    for file_name in os.listdir(certificatesPath):
        file_path = certificatesPath + '/' + file_name
        if file_path.endswith('.p12') or file_path.endswith('.cer'):
            print('importing {}: {}'.format(file_name, run_executable_with_output('security', arguments=[
                'import',
                file_path,
                '-k',
                keychain_name,
                '-P',
                '',
                '-T',
                '/usr/bin/codesign',
                '-T',
                '/usr/bin/security'
            ], check_result=False)))

    run_executable_with_output('security', arguments=[
        'import',
        'build-system/AppleWWDRCAG3.cer',
        '-k',
        keychain_name,
        '-P',
        '',
        '-T',
        '/usr/bin/codesign',
        '-T',
        '/usr/bin/security'
    ], check_result=False)

    run_executable_with_output('security', arguments=[
        'set-key-partition-list',
        '-S',
        'apple-tool:,apple:',
        '-k',
        keychain_password,
        keychain_name
    ], check_result=True)

    run_executable_with_output('security', arguments=['default-keychain', '-s', keychain_name], check_result=False)
    run_executable_with_output('security', arguments=['set-keychain-settings', '-t', '21600', '-u', keychain_name], check_result=False)

    # the signing certificate is self-signed, so macOS treats it as an invalid
    # codesigning identity until it is explicitly trusted as a root
    for file_name in sorted(os.listdir(certificatesPath)):
        if file_name.endswith('.cer'):
            print('trusting {}: {}'.format(file_name, run_executable_with_output('sudo', arguments=[
                'security', 'add-trusted-cert', '-d', '-r', 'trustRoot',
                '-k', '/Library/Keychains/System.keychain', certificatesPath + '/' + file_name
            ], check_result=False)))

    identities = find_codesigning_identities(keychain_name)

    if not has_identity(identities):
        print('All identities, including invalid ones: {}'.format(run_executable_with_output('security', arguments=[
            'find-identity', '-p', 'codesigning', keychain_name
        ], check_result=False)))

    if not has_identity(identities):
        # recent macOS releases refuse to import PKCS#12 files encrypted with the
        # legacy RC2-40 cipher, so re-wrap them in AES-256 and import again
        for file_name in sorted(os.listdir(certificatesPath)):
            if not file_name.endswith('.p12'):
                continue
            source_path = certificatesPath + '/' + file_name
            pem_path = '/tmp/{}.pem'.format(file_name)
            modern_path = '/tmp/modern-{}'.format(file_name)
            run_executable_with_output('openssl', arguments=[
                'pkcs12', '-in', source_path, '-passin', 'pass:', '-nodes', '-out', pem_path
            ], check_result=True)
            # an empty PKCS#12 password makes macOS fail MAC verification, so set a real one
            run_executable_with_output('openssl', arguments=[
                'pkcs12', '-export', '-in', pem_path, '-out', modern_path, '-passout', 'pass:' + keychain_password,
                '-keypbe', 'aes-256-cbc', '-certpbe', 'aes-256-cbc'
            ], check_result=True)
            run_executable_with_output('security', arguments=[
                'import', modern_path, '-k', keychain_name, '-P', keychain_password,
                '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'
            ], check_result=True)

        run_executable_with_output('security', arguments=[
            'set-key-partition-list', '-S', 'apple-tool:,apple:', '-k', keychain_password, keychain_name
        ], check_result=True)
        identities = find_codesigning_identities(keychain_name)

    if not has_identity(identities):
        print('No codesigning identity is available after importing {}'.format(certificatesPath))
        print('Search list: {}'.format(run_executable_with_output('security', arguments=['list-keychains'], check_result=False)))
        sys.exit(1)


def find_codesigning_identities(keychain_name):
    identities = run_executable_with_output('security', arguments=[
        'find-identity', '-v', '-p', 'codesigning', keychain_name
    ], check_result=False)
    print('Codesigning identities in {}: {}'.format(keychain_name, identities))
    return identities


def has_identity(identities):
    return 'Apple Distribution' in identities or 'Apple Development' in identities or 'iPhone Distribution' in identities


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='build')

    parser.add_argument(
        '--path',
        required=True,
        help='Path to certificates.'
    )

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    import_certificates(args.path)
