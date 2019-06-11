import asyncio
import time
from indy import anoncreds, crypto, did, ledger, pool, wallet

import json
from typing import Optional


async def run():
    print("Getting started -> started")

    # Set protocol version 2 to work with Indy Node 1.4

    await pool.set_protocol_version(2)

    # Kode untuk Steward Agent, utk getting started, dia bakal create pool.
    pool_ = {
        'name': 'pool1',
        'config': json.dumps({"genesis_txn": '/home/indy/sandbox/pool_transactions_genesis'})
    }
    print("Open Pool Ledger: {}".format(pool_['name']))

    try:
        await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'], None)

    print("==============================")
    print("=== Getting Trust Anchor credentials for Faber, Acme, GS-50 and Government  ==")
    print("------------------------------")

    print("\"Sovrin Steward\" -> Create wallet")
    steward = {
        'name': "Sovrin Steward",
        'wallet_config': json.dumps({'id': 'sovrin_steward_wallet'}),
        'wallet_credentials': json.dumps({'key': 'steward_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
        #Kenapa nggak ada role-nya ya? Atau udah direstrict penggunaan var steward cm buat steward?
        #karena: the first code block will contain the code of the Steward's agent.
    }

    try:
        await wallet.create_wallet(steward['wallet_config'], steward['wallet_credentials'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            pass

    steward['wallet'] = await wallet.open_wallet(steward['wallet_config'], steward['wallet_credentials'])

    print("\"Sovrin Steward\" -> Create and store in Wallet DID from seed")
    steward['did_info'] = json.dumps({'seed': steward['seed']})
    steward['did'], steward['key'] = await did.create_and_store_my_did(steward['wallet'], steward['did_info'])

    print("==============================")
    print("== Getting Trust Anchor credentials - Government Onboarding  ==")
    print("------------------------------")

    government = {
        'name': 'Government',
        'wallet_config': json.dumps({'id': 'government_wallet'}),
        'wallet_credentials': json.dumps({'key': 'government_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    steward['did_for_government'], steward['key_for_government'], government['did_for_steward'], \
    government['key_for_steward'], _ = await onboarding(steward, government)

    print("==============================")
    print("== Getting Trust Anchor credentials - Government getting Verinym  ==")
    print("------------------------------")

    government['did'] = await get_verinym(steward, steward['did_for_government'], steward['key_for_government'],
                                          government, government['did_for_steward'], government['key_for_steward'])

    print("==============================")
    print("== Getting Trust Anchor credentials - KS-Telecom Onboarding  ==")
    print("------------------------------")

    ks = {
        'name': 'KS-Telecom',
        'wallet_config': json.dumps({'id': 'ks_wallet'}),
        'wallet_credentials': json.dumps({'key': 'ks_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    steward['did_for_ks'], steward['key_for_ks'], ks['did_for_steward'], ks['key_for_steward'], _ = \
        await onboarding(steward, ks)

    print("==============================")
    print("== Getting Trust Anchor credentials - KS-Telecom getting Verinym  ==")
    print("------------------------------")

    ks['did'] = \
        await get_verinym(steward, steward['did_for_ks'], steward['key_for_ks'],
                          ks, ks['did_for_steward'], ks['key_for_steward'])

    print("==============================")
    print("== Getting Trust Anchor credentials - GS-50 Onboarding  ==")
    print("------------------------------")

    gs = {
        'name': 'GS-50',
        'wallet_config': json.dumps({'id': 'gs_wallet'}),
        'wallet_credentials': json.dumps({'key': 'gs_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    steward['did_for_gs'], steward['key_for_gs'], gs['did_for_steward'], gs['key_for_steward'], _ = \
        await onboarding(steward, gs)

    print("==============================")
    print("== Getting Trust Anchor credentials - GS-50 getting Verinym  ==")
    print("------------------------------")

    gs['did'] = await get_verinym(steward, steward['did_for_gs'], steward['key_for_gs'],
                                    gs, gs['did_for_steward'], gs['key_for_steward'])

    """"
    print("==============================")
    print("== Getting Trust Anchor credentials - GS-50 Onboarding  ==")
    print("------------------------------")

    gs = {
        'name': 'GS-50',
        'wallet_config': json.dumps({'id': 'gs_wallet'}),
        'wallet_credentials': json.dumps({'key': 'gs_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    steward['did_for_gs'], steward['key_for_gs'], gs['did_for_steward'], gs['key_for_steward'], _ = \
        await onboarding(steward, gs)

    print("==============================")
    print("== Getting Trust Anchor credentials - GS-50 getting Verinym  ==")
    print("------------------------------")

    gs['did'] = await get_verinym(steward, steward['did_for_gs'], steward['key_for_gs'],
                                      gs, gs['did_for_steward'], gs['key_for_steward'])

    print("==============================")
    """
    print("=== Credential Schemas Setup ==")
    print("------------------------------")

    print("\"Government\" -> Create \"Citizen's Basic Information (CBI)\" Schema")
    cbi = {
        'name': 'CBI-Certificate',
        'version': '2.0',
        'attributes': ['first_name', 'last_name', 'dob', 'ssn']
    }
    (government['cbi_certificate_schema_id'], government['cbi_certificate_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], cbi_certificate['name'], cbi_certificate['version'],
                                             json.dumps(cbi_certificate['attributes']))
    cbi_certificate_schema_id = government['cbi_certificate_schema_id']

    print("\"Government\" -> Send \"CBI-Certificate\" Schema to Ledger")
    await send_schema(government['pool'], government['wallet'], government['did'], government['cbi_certificate_schema'])

    print("\"Government\" -> Create \"Telecom Registration Certificate (TRC)\" Schema")
    transcript = {
        'name': 'TRC-Certificate',
        'version': '1.0',
        'attributes': ['first_name', 'last_name', 'phone_no', 'ssn', 'date_of_registration', 'plan_type', 'status']
    }
    (government['trc_certificate_schema_id'], government['trc_certificate_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], trc_certificate['name'], trc_certificate['version'],
                                             json.dumps(trc_certificate['attributes']))
    trc_certificate_schema_id = government['trc_certificate_schema_id']

    print("\"Government\" -> Send \"CBI-Certificate\" Schema to Ledger")
    await send_schema(government['pool'], government['wallet'], government['did'], government['trc_certificate_schema'])

    time.sleep(1)  # sleep 1 second before getting schema

    print("==============================")
    print("=== KS-Telecom Credential Definition Setup ==")
    print("------------------------------")

    print("\"KS-Telecom\" -> Get \"TRC\" Schema from Ledger")
    (ks['trc_certificate_schema_id'], ks['trc_certificate_schema_schema']) = \
        await get_schema(ks['pool'], ks['did'], trc_certificate_schema_id)

    print("\"KS-Telecom\" -> Create and store in Wallet \"TRC-Certificate\" Credential Definition")
    trc_certificate_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": True}
    }
    (ks['trc_certificate_cred_def_id'], ks['trc_certificate_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(ks['wallet'], ks['did'],
                                                               ks['trc_certificate_schema'], trc_certificate_cred_def['tag'],
                                                               trc_certificate_cred_def['type'],
                                                               json.dumps(trc_certificate_cred_def['config'])) #bisa add ks['cbi_certificate_schema'] ga ya? nanti cobain

    print("\"KS-Telecom\" -> Send  \"TRC-Certificate\" Credential Definition to Ledger")
    await send_cred_def(ks['pool'], ks['wallet'], ks['did'], ks['transcript_cred_def'])
    '''
    butuh ga? kan GS cuma butuh liat ke ledger?
    print("==============================")
    print("=== GS-50 Credential Definition Setup ==")
    print("------------------------------")

    print("\"Acme\" -> Get from Ledger \"Job-Certificate\" Schema")
    (ks['job_certificate_schema_id'], ks['job_certificate_schema']) = \
        await get_schema(ks['pool'], ks['did'], job_certificate_schema_id)

    print("\"Acme\" -> Create and store in Wallet \"Acme Job-Certificate\" Credential Definition")
    job_certificate_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (ks['job_certificate_cred_def_id'], ks['job_certificate_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(ks['wallet'], ks['did'],
                                                               ks['job_certificate_schema'],
                                                               job_certificate_cred_def['tag'],
                                                               job_certificate_cred_def['type'],
                                                               json.dumps(job_certificate_cred_def['config']))

    print("\"Acme\" -> Send \"Acme Job-Certificate\" Credential Definition to Ledger")
    await send_cred_def(ks['pool'], ks['wallet'], ks['did'], ks['job_certificate_cred_def'])
    '''
    print("==============================")
    print("=== Getting CBI-Certificate with Government ==")
    print("==============================")
    print("== Getting Transcript with Government - Onboarding ==")
    print("------------------------------")

    alice = {
        'name': 'Alice',
        'wallet_config': json.dumps({'id': 'alice_wallet'}),
        'wallet_credentials': json.dumps({'key': 'alice_wallet_key'}),
        'pool': pool_['handle'],
    }
    government['did_for_alice'], government['key_for_alice'], alice['did_for_government'], alice['key_for_government'], \
    government['alice_connection_response'] = await onboarding(government, alice)

    print("==============================")
    print("== Getting CBI-Certificate with Government - Getting CBI-Certificate Credential ==")
    print("------------------------------")

    print("\"Government\" -> Create \"CBI-Certificate\" Credential Offer for Alice")
    government['cbi_certificate_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(government['wallet'], government['cbi_certificate_cred_def_id'])

    print("\"Government\" -> Get key for Alice did")
    government['alice_key_for_government'] = \
        await did.key_for_did(government['pool'], government['wallet'], government['alice_connection_response']['did'])

    print("\"Government\" -> Authcrypt \"CBI-Certificate\" Credential Offer for Alice")
    faber['authcrypted_cbi_certificate_cred_offer'] = \
        await crypto.auth_crypt(government['wallet'], government['key_for_alice'], government['alic_key_for_government'],
                                government['cbi_certificate_cred_offer'].encode('utf-8'))

    print("\"Government\" -> Send authcrypted \"CBI-certificate\" Credential Offer to Alice")
    alice['authcrypted_cbi_certificate_cred_offer'] = government['authcrypted_cbi_certificate_cred_offer']

    print("\"Alice\" -> Authdecrypted \"CBI-Certificate\" Credential Offer from Government")
    alice['government_key_for_alice'], alice['cbi_certificate_cred_offer'], authdecrypted_cbi_certificate_cred_offer = \
        await auth_decrypt(alice['wallet'], alice['key_for_government'], alice['authcrypted_cbi_certificate_cred_offer'])
    alice['cbi_certificate_schema_id'] = authdecrypted_cbi_certificate_cred_offer['schema_id']
    alice['cbi_certificate_cred_def_id'] = authdecrypted_cbi_certificate_cred_offer['cred_def_id']

    print("\"Alice\" -> Create and store \"Alice\" Master Secret in Wallet")
    alice['master_secret_id'] = await anoncreds.prover_create_master_secret(alice['wallet'], None)

    print("\"Alice\" -> Get \"Government's CBI-Certificate\" Credential Definition from Ledger")
    (alice['government_cbi_certificate_cred_def_id'], alice['government_cbi_certificate_cred_def']) = \
        await get_cred_def(alice['pool'], alice['did_for_government'], authdecrypted_cbi_certificate_cred_offer['cred_def_id'])

    print("\"Alice\" -> Create \"CBI-Certificate\" Credential Request for Government")
    (alice['cbi_certificate_cred_request'], alice['cbi_certificate_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(alice['wallet'], alice['did_for_government'],
                                                     alice['cbi_certificate_cred_offer'], alice['government_cbi_certificate_cred_def'],
                                                     alice['master_secret_id'])

    print("\"Alice\" -> Authcrypt \"CBI Certificate\" Credential Request for Government")
    alice['authcrypted_cbi_certificate_cred_request'] = \
        await crypto.auth_crypt(alice['wallet'], alice['key_for_government'], alice['government_key_for_alice'],
                                alice['cbi_certificate_cred_request'].encode('utf-8'))

    print("\"Alice\" -> Send authcrypted \"CBI Certificate\" Credential Request to Government")
    alice['cbi_certificate_cred_values'] = json.dumps({
        "first_name": {"raw": "Alice", "encoded": "1139481716457488690172217916278103335"},
        "last_name": {"raw": "Garcia", "encoded": "5321642780241790123587902456789123452"},
        "dob": {"raw": "19920810", "encoded": "2213454313412354"}, #encoded to what?
        "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
    })
    government['authcrypted_cbi_certificate_cred_request'] = alice['authcrypted_cbi_certificate_cred_request']
    government['alice_cbi_certificate_cred_values'] = alice['cbi_certificate_cred_values']

    print("\"Government\" -> Authdecrypt \"CBI-Certificate\" Credential Request from Alice")
    government['alice_key_for_government'], government['cbi_certificate_cred_request'], _ = \
        await auth_decrypt(government['wallet'], government['key_for_alice'], government['authcrypted_cbi_certificate_cred_request'])

    print("\"Government\" -> Create \"CBI Certificate\" Credential for Alice")

    government['transcript_cred'], _, _ = \
        await anoncreds.issuer_create_credential(government['wallet'], government['cbi_certificate_cred_offer'],
                                                 government['cbi_certificate_cred_request'],
                                                 government['alice_cbi_certificate_cred_values'], None, None)

    print("\"Government\" -> Authcrypt \"CBI-Certificate\" Credential for Alice")
    government['authcrypted_transcript_cred'] = \
        await crypto.auth_crypt(government['wallet'], government['key_for_alice'], government['alice_key_for_government'],
                                government['cbi_certificate_cred'].encode('utf-8'))

    print("\"Government\" -> Send authcrypted \"CBI-Certificate\" Credential to Alice")
    alice['authcrypted_cbi_certificate_cred'] = government['authcrypted_cbi_certificate_cred']

    print("\"Alice\" -> Authdecrypted \"CBI-Certificate\" Credential from Government")
    _, alice['cbi_certificate_cred'], _ = \
        await auth_decrypt(alice['wallet'], alice['key_for_government'], alice['authcrypted_cbi_certificate_cred'])

    print("\"Alice\" -> Store \"CBI-Certificate\" Credential from Government")
    _, alice['cbi_certificate_cred_def'] = await get_cred_def(alice['pool'], alice['did_for_government'],
                                                         alice['cbi_certificate_cred_def_id'])

    await anoncreds.prover_store_credential(alice['wallet'], None, alice['cbi_certificate_cred_request_metadata'],
                                            alice['cbi_certificate_cred'], alice['cbi_certificate_cred_def'], None)

    print("==============================")
    print("=== Apply for the telecommunication service with KS-Telecom ==")
    print("==============================")
    print("== Apply for the telecommunication service with KS-Telecom - Onboarding ==")
    print("------------------------------")

    ks['did_for_alice'], ks['key_for_alice'], alice['did_for_ks'], alice['key_for_ks'], \
    ks['alice_connection_response'] = await onboarding(ks, alice)

    print("==============================")
    print("== Apply for the telecommunication service with KS-Telecom - CBI-Certificate proving ==")
    print("------------------------------")
#Br smp sini. Restrictions tuh liat dari nilai cred_def_id!
    print("\"KS-Telecom\" -> Create \"Registration-Requirement\" Proof Request")
    ks['trc_certificate_proof_request'] = json.dumps({
        'nonce': '1432422343242122312411212',
        'name': 'TRC-Certificate',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name',
                'restrictions': [{'cred_def_id': government['cbi_certificate_cred_def_id']}]
            },
            'attr2_referent': {
                'name': 'last_name',
                'restrictions': [{'cred_def_id': government['cbi_certificate_cred_def_id']}]
            },
            'attr3_referent': {
                'name': 'ssn',
                'restrictions': [{'cred_def_id': government['cbi_certificate_cred_def_id']}]
            }
        }
    })

    print("\"KS-Telecom\" -> Get key for Alice's DID")
    ks['alice_key_for_ks'] = \
        await did.key_for_did(ks['pool'], ks['wallet'], ks['alice_connection_response']['did'])

    print("\"KS-Telecom\" -> Authcrypt \"Registration-Requirement\" Proof Request for Alice")
    ks['authcrypted_registration_req_proof_request'] = \
        await crypto.auth_crypt(ks['wallet'], ks['key_for_alice'], ks['alice_key_for_ks'],
                                ks['registration_req_proof_request'].encode('utf-8'))

    print("\"KS-Telecom\" -> Send authcrypted \"Registration-Requirement\" Proof Request to Alice")
    alice['authcrypted_registration_req_proof_request'] = ks['authcrypted_registration_req_proof_request']

    print("\"Alice\" -> Authdecrypt \"Registration-Requirement\" Proof Request from KS-Telecom")
    alice['ks_key_for_alice'], alice['registration_req_proof_request'], _ = \
        await auth_decrypt(alice['wallet'], alice['key_for_ks'], alice['authcrypted_registration_req_proof_request'])

    print("\"Alice\" -> Get credentials for \"Registration-Requirement\" Proof Request")

    search_for_registration_req_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(alice['wallet'],
                                                                alice['registration_req_proof_request'], None)

    cred_for_attr1 = await get_credential_for_referent(search_for_registration_req_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_registration_req_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_registration_req_proof_request, 'attr3_referent')
    #ini buat apa? kok cum apredicate1 doang? ooh buat cek memenuhi atau ga. Here, gabutuh.
    """
    cred_for_predicate1 = \
        await get_credential_for_referent(search_for_registration_req_proof_request, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_registration_req_proof_request)

    alice['creds_for_registration_req_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                cred_for_attr2['referent']: cred_for_attr2,
                                                cred_for_attr3['referent']: cred_for_attr3,
                                                cred_for_predicate1['referent']: cred_for_predicate1}
    """

    alice['schemas'], alice['cred_defs'], alice['revoc_states'] = \
        await prover_get_entities_from_ledger(alice['pool'], alice['did_for_ks'],
                                              alice['creds_for_registration_req_proof'], alice['name'])

    print("\"Alice\" -> Create \"Registration-Requirement\" Proof")
    alice['registration_req_requested_creds'] = json.dumps({
    #here, gak ada self-attested attribute
        'requested_attributes': {
            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
            'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True},
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
        }
    #here, ga ada requested predicate
    })

    alice['job_application_proof'] = \
        await anoncreds.prover_create_proof(alice['wallet'], alice['registration_req_proof_request'],
                                            alice['registration_req_requested_creds'], alice['master_secret_id'],
                                            alice['schemas'], alice['cred_defs'], alice['revoc_states'])

    print("\"Alice\" -> Authcrypt \"Registration-Requirement\" Proof for KS-Telecom")
    alice['authcrypted_registration_req_proof'] = \
        await crypto.auth_crypt(alice['wallet'], alice['key_for_ks'], alice['ks_key_for_alice'],
                                alice['registration_req_proof'].encode('utf-8'))

    print("\"Alice\" -> Send authcrypted \"Registration-Requirement\" Proof to KS-Telecom")
    ks['authcrypted_registration_req_proof'] = alice['authcrypted_registration_req_proof']

    print("\"Acme\" -> Authdecrypted \"Registration-Requirement\" Proof from Alice")
    _, ks['registration_req_proof'], decrypted_registration_req_proof = \
        await auth_decrypt(ks['wallet'], ks['key_for_alice'], ks['authcrypted_registration_req_proof'])

    ks['schemas'], ks['cred_defs'], ks['revoc_ref_defs'], ks['revoc_regs'] = \
        await verifier_get_entities_from_ledger(ks['pool'], ks['did'],
                                                decrypted_registration_req_proof['identifiers'], ks['name'])
#br smp sini
    print("\"KS-Telecom\" -> Verify \"Registration-Requirement\" Proof from Alice")
    assert 'Alice' == \
           decrypted_registration_req_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
    assert 'Garcia' == \
           decrypted_registration_req_proof['requested_proof']['revealed_attrs']['attr2_referent']['raw']
    assert '123-45-6789' == \
           decrypted_registration_req_proof['requested_proof']['revealed_attrs']['attr4_referent']['raw']
#here ada self-attested attribute, tapi kita ga ada, jadi ga kepake
    """
    assert 'Alice' == decrypted_registration_req_proof['requested_proof']['self_attested_attrs']['attr1_referent']
    assert 'Garcia' == decrypted_registration_req_proof['requested_proof']['self_attested_attrs']['attr2_referent']
    assert '123-45-6789' == decrypted_registration_req_proof['requested_proof']['self_attested_attrs']['attr4_referent']
    """

    assert await anoncreds.verifier_verify_proof(ks['registration_req_proof_request'], ks['registration_req_proof'],
                                                 ks['schemas'], ks['cred_defs'], ks['revoc_ref_defs'],
                                                 ks['revoc_regs'])

    print("==============================")
    print("== Alice Getting TRC Credential from KS-Telecom==")
    print("------------------------------")

    print("\"KS-Telecom\" -> Create \"TRC-Certificate\" Credential Offer for Alice")
    ks['trc_certificate_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(ks['wallet'], ks['trc_certificate_cred_def_id'])

    print("\"KS-Telecom\" -> Get key for Alice did")
    ks['alice_key_for_ks'] = \
        await did.key_for_did(ks['pool'], ks['wallet'], ks['alice_connection_response']['did'])

    print("\"KS-Telecom\" -> Authcrypt \"TRC-Certificate\" Credential Offer for Alice")
    ks['authcrypted_job_certificate_cred_offer'] = \
        await crypto.auth_crypt(ks['wallet'], ks['key_for_alice'], ks['alice_key_for_ks'],
                                ks['trc_certificate_cred_offer'].encode('utf-8'))

    print("\"KS-Telecom\" -> Send authcrypted \"TRC-Certificate\" Credential Offer to Alice")
    alice['authcrypted_trc_certificate_cred_offer'] = ks['authcrypted_trc_certificate_cred_offer']

    print("\"Alice\" -> Authdecrypted \"TRC-Certificate\" Credential Offer from KS-Telecom")
    alice['ks_key_for_alice_alice'], alice['trc_certificate_cred_offer'], job_certificate_cred_offer = \
        await auth_decrypt(alice['wallet'], alice['key_for_ks'], alice['authcrypted_trc_certificate_cred_offer'])

    print("\"Alice\" -> Get \"TRC-Certificate\" Credential Definition from Ledger")
    (alice['ks_trc_certificate_cred_def_id'], alice['ks_trc_certificate_cred_def']) = \
        await get_cred_def(alice['pool'], alice['did_for_ks'], trc_certificate_cred_offer['cred_def_id'])

    print("\"Alice\" -> Create and store in Wallet \"TRC-Certificate\" Credential Request for KS-Telecom")
    (alice['trc_certificate_cred_request'], alice['trc_certificate_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(alice['wallet'], alice['did_for_ks'],
                                                     alice['trc_certificate_cred_offer'],
                                                     alice['ks_trc_certificate_cred_def'], alice['master_secret_id'])

    print("\"Alice\" -> Authcrypt \"TRC-Certificate\" Credential Request for KS-Telecom")
    alice['authcrypted_job_certificate_cred_request'] = \
        await crypto.auth_crypt(alice['wallet'], alice['key_for_ks'], alice['ks_key_for_alice'],
                                alice['trc_certificate_cred_request'].encode('utf-8'))

    print("\"Alice\" -> Send authcrypted \"TRC-Certificate\" Credential Request to KS-Telecom")
    alice['trc_certificate_cred_values'] = json.dumps({
    #encoded belum diganti
        "first_name": {"raw": "Alice", "encoded": "245712572474217942457235975012103335"},
        "last_name": {"raw": "Garcia", "encoded": "312643218496194691632153761283356127"},
        "phone_no": {"raw": "010-8877-8877", "encoded": "2143135425425143112321314321"},
        "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
        "date_of_registration": {"raw": "20190520", "encoded": "20190520"}
    })
    ks['authcrypted_trc_certificate_cred_request'] = alice['authcrypted_trc_certificate_cred_request']
    ks['trc_certificate_cred_values'] = alice['trc_certificate_cred_values']

    print("\"KS-Telecom\" -> Authdecrypt \"TRC-Certificate\" Credential Request from Alice")
    ks['alice_key_for_ks'], ks['trc_certificate_cred_request'], _ = \
        await auth_decrypt(ks['wallet'], ks['key_for_alice'], ks['authcrypted_trc_certificate_cred_request'])

    print("\"KS-Telecom\" -> Create \"TRC-Certificate\" Credential for Alice")

    ks['trc_certificate_cred'], _, _ = \
        await anoncreds.issuer_create_credential(ks['wallet'], ks['trc_certificate_cred_offer'],
                                                 ks['trc_certificate_cred_request'],
                                                 ks['trc_certificate_cred_values'], None, None)

    print("\"KS-Telecom\" -> Authcrypt \"TRC-Certificate\" Credential for Alice")
    ks['authcrypted_trc_certificate_cred'] = \
        await crypto.auth_crypt(ks['wallet'], ks['key_for_alice'], ks['alice_key_for_ks'],
                                ks['trc_certificate_cred'].encode('utf-8'))

    print("\"KS-Telecom\" -> Send authcrypted \"TRC-Certificate\" Credential to Alice")
    alice['authcrypted_trc_certificate_cred'] = ks['authcrypted_trc_certificate_cred']

    print("\"Alice\" -> Authdecrypted \"TRC-Certificate\" Credential from KS-Telecom")
    _, alice['trc_certificate_cred'], _ = \
        await auth_decrypt(alice['wallet'], alice['key_for_ks'], alice['authcrypted_trc_certificate_cred'])

    print("\"Alice\" -> Store \"TRC-Certificate\" Credential")
    await anoncreds.prover_store_credential(alice['wallet'], None, alice['trc_certificate_cred_request_metadata'],
                                            alice['trc_certificate_cred'],
                                            alice['ks_trc_certificate_cred_def'], None)

    print("==============================")
    print("=== Apply for a Discount at GS-50 ==")
    print("==============================")
    print("== Apply for a Discount at GS-50 - Onboarding ==")
    print("------------------------------")

    gs['did_for_alice'], gs['key_for_alice'], alice['did_for_gs'], alice['key_for_gs'], \
    gs['alice_connection_response'] = await onboarding(gs, alice)

    print("==============================")
    print("== Apply for a Discount at GS-50 - KS-Telecom Subscription Proving  ==")
    print("------------------------------")

    print("\"GS-50\" -> Create \"Membership\" Proof Request")
    gs['apply_membership_proof_request'] = json.dumps({
        'nonce': '123432421212',
        'name': 'KS-Telecom Membership',
        'version': '0.1',

    #kita gaada requested attribute, cuma predicate
"""
        'requested_attributes': {
            'attr1_referent': {
                'name': 'status',
                'restrictions': [{'cred_def_id': ks['trc_certificate_cred_def_id']}]
            }
        },
"""
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'status',
                'p_type': '=',
                'p_value': active,
                'restrictions': [{'cred_def_id': ks['crt_certificate_cred_def_id']}]
            }
        }
    })

    print("\"GS-50\" -> Get key for Alice did")
    gs['alice_key_for_gs'] = \
        await did.key_for_did(gs['pool'], gs['wallet'], gs['alice_connection_response']['did'])

    print("\"GS-50\" -> Authcrypt \"Membership\" Proof Request for Alice")
    gs['authcrypted_apply_membership_proof_request'] = \
        await crypto.auth_crypt(gs['wallet'], gs['key_for_alice'], gs['alice_key_for_gs'],
                                gs['apply_membership_proof_request'].encode('utf-8'))

    print("\"GS-50\" -> Send authcrypted \"Membership\" Proof Request to Alice")
    alice['authcrypted_apply_membership_proof_request'] = gs['authcrypted_apply_membership_proof_request']

    print("\"Alice\" -> Authdecrypt \"Membership\" Proof Request from GS-50")
    alice['gs_key_for_alice'], alice['apply_membership_proof_request'], _ = \
        await auth_decrypt(alice['wallet'], alice['key_for_gs'], alice['authcrypted_apply_membership_proof_request'])

    print("\"Alice\" -> Get credentials for \"Membership\" Proof Request")

    search_for_apply_membership_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(alice['wallet'],
                                                                alice['apply_membership_proof_request'], None)

    cred_for_predicate1 = await get_credential_for_referent(search_for_apply_membership_proof_request, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_membership_proof_request)

    alice['creds_for_apply_membership_proof'] = {cred_for_predicate1['referent']: cred_for_predicate1}

    alice['schemas'], alice['cred_defs'], alice['revoc_states'] = \
        await prover_get_entities_from_ledger(alice['pool'], alice['did_for_gs'],
                                              alice['creds_for_apply_membership_proof'],
                                              alice['name'])

    print("\"Alice\" -> Create \"Membership\" Proof")
    alice['apply_membership_requested_creds'] = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {},
        'requested_predicates': {
            'predicate1_referent': {'cred_id': cred_for_predicate1['referent']} #gak ada revealed true ky contoh yg requested attribute, gapapa or gimans?
        }
    })
    alice['apply_membership_proof'] = \
        await anoncreds.prover_create_proof(alice['wallet'], alice['apply_membership_proof_request'],
                                            alice['apply_membership_requested_creds'], alice['master_secret_id'],
                                            alice['schemas'], alice['cred_defs'], alice['revoc_states'])

    print("\"Alice\" -> Authcrypt \"Membership\" Proof for GS-50")
    alice['authcrypted_alice_apply_membership_proof'] = \
        await crypto.auth_crypt(alice['wallet'], alice['key_for_gs'], alice['gs_key_for_alice'],
                                alice['apply_membership_proof'].encode('utf-8'))

    print("\"Alice\" -> Send authcrypted \"Membership\" Proof to GS-50")
    gs['authcrypted_alice_apply_membership_proof'] = alice['authcrypted_alice_apply_membership_proof']

    print("\"GS-50\" -> Authdecrypted \"Membership\" Proof from Alice")
    _, gs['alice_apply_membership_proof'], authdecrypted_alice_apply_membership_proof = \
        await auth_decrypt(gs['wallet'], gs['key_for_alice'], gs['authcrypted_alice_apply_membership_proof'])

    print("\"GS-50\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                " required for Proof verifying")

    gs['schemas'], gs['cred_defs'], gs['revoc_defs'], gs['revoc_regs'] = \
        await verifier_get_entities_from_ledger(gs['pool'], gs['did'],
                                                authdecrypted_alice_apply_membership_proof['identifiers'], gs['name'])

    print("\"GS-50\" -> Verify \"Membership\" Proof from Alice")
    assert 'active' == \
           authdecrypted_alice_apply_loan_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw'] #in our case ini predicate, bukan attribute. Gimanas?

    assert await anoncreds.verifier_verify_proof(gs['apply_membership_proof_request'], gs['alice_apply_membership_proof'],
                                                 gs['schemas'], gs['cred_defs'], gs['revoc_defs'],
                                                 gs['revoc_regs'])

    """ Kita gaada fase KYC sih, buang ae?

    print("==============================")

    print("==============================")
    print("== Apply for the loan with GS-50 - Transcript and Job-Certificate proving  ==")
    print("------------------------------")

    print("\"GS-50\" -> Create \"Loan-Application-KYC\" Proof Request")
    gs['apply_loan_kyc_proof_request'] = json.dumps({
        'nonce': '123432421212',
        'name': 'Loan-Application-KYC',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {'name': 'first_name'},
            'attr2_referent': {'name': 'last_name'},
            'attr3_referent': {'name': 'ssn'}
        },
        'requested_predicates': {}
    })

    print("\"GS-50\" -> Get key for Alice did")
    gs['alice_key_for_gs'] = await did.key_for_did(gs['pool'], gs['wallet'],
                                                           gs['alice_connection_response']['did'])

    print("\"GS-50\" -> Authcrypt \"Loan-Application-KYC\" Proof Request for Alice")
    gs['authcrypted_apply_loan_kyc_proof_request'] = \
        await crypto.auth_crypt(gs['wallet'], gs['key_for_alice'], gs['alice_key_for_gs'],
                                gs['apply_loan_kyc_proof_request'].encode('utf-8'))

    print("\"GS-50\" -> Send authcrypted \"Loan-Application-KYC\" Proof Request to Alice")
    alice['authcrypted_apply_loan_kyc_proof_request'] = gs['authcrypted_apply_loan_kyc_proof_request']

    print("\"Alice\" -> Authdecrypt \"Loan-Application-KYC\" Proof Request from GS-50")
    alice['gs_key_for_alice'], alice['apply_loan_kyc_proof_request'], _ = \
        await auth_decrypt(alice['wallet'], alice['key_for_gs'], alice['authcrypted_apply_loan_kyc_proof_request'])

    print("\"Alice\" -> Get credentials for \"Loan-Application-KYC\" Proof Request")

    search_for_apply_loan_kyc_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(alice['wallet'],
                                                                alice['apply_loan_kyc_proof_request'], None)

    cred_for_attr1 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr3_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_loan_kyc_proof_request)

    alice['creds_for_apply_loan_kyc_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                               cred_for_attr2['referent']: cred_for_attr2,
                                               cred_for_attr3['referent']: cred_for_attr3}

    alice['schemas'], alice['cred_defs'], alice['revoc_states'] = \
        await prover_get_entities_from_ledger(alice['pool'], alice['did_for_gs'],
                                              alice['creds_for_apply_loan_kyc_proof'], 'Alice')

    print("\"Alice\" -> Create \"Loan-Application-KYC\" Proof")

    alice['apply_loan_kyc_requested_creds'] = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {
            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
            'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True},
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True}
        },
        'requested_predicates': {}
    })

    alice['apply_loan_kyc_proof'] = \
        await anoncreds.prover_create_proof(alice['wallet'], alice['apply_loan_kyc_proof_request'],
                                            alice['apply_loan_kyc_requested_creds'], alice['master_secret_id'],
                                            alice['schemas'], alice['cred_defs'], alice['revoc_states'])

    print("\"Alice\" -> Authcrypt \"Loan-Application-KYC\" Proof for GS-50")
    alice['authcrypted_alice_apply_loan_kyc_proof'] = \
        await crypto.auth_crypt(alice['wallet'], alice['key_for_gs'], alice['gs_key_for_alice'],
                                alice['apply_loan_kyc_proof'].encode('utf-8'))

    print("\"Alice\" -> Send authcrypted \"Loan-Application-KYC\" Proof to GS-50")
    gs['authcrypted_alice_apply_loan_kyc_proof'] = alice['authcrypted_alice_apply_loan_kyc_proof']

    print("\"GS-50\" -> Authdecrypted \"Loan-Application-KYC\" Proof from Alice")
    _, gs['alice_apply_loan_kyc_proof'], alice_apply_loan_kyc_proof = \
        await auth_decrypt(gs['wallet'], gs['key_for_alice'], gs['authcrypted_alice_apply_loan_kyc_proof'])

    print("\"GS-50\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                " required for Proof verifying")

    gs['schemas'], gs['cred_defs'], gs['revoc_defs'], gs['revoc_regs'] = \
        await verifier_get_entities_from_ledger(gs['pool'], gs['did'],
                                                alice_apply_loan_kyc_proof['identifiers'], 'GS-50')

    print("\"GS-50\" -> Verify \"Loan-Application-KYC\" Proof from Alice")
    assert 'Alice' == \
           alice_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
    assert 'Garcia' == \
           alice_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr2_referent']['raw']
    assert '123-45-6789' == \
           alice_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']

    assert await anoncreds.verifier_verify_proof(gs['apply_loan_kyc_proof_request'],
                                                 gs['alice_apply_loan_kyc_proof'],
                                                 gs['schemas'], gs['cred_defs'], gs['revoc_defs'],
                                                 gs['revoc_regs'])

    """

    print("==============================")

    print(" \"Sovrin Steward\" -> Close and Delete wallet")
    await wallet.close_wallet(steward['wallet'])
    await wallet.delete_wallet(steward['wallet_config'], steward['wallet_credentials'])

    print("\"Government\" -> Close and Delete wallet")
    await wallet.close_wallet(government['wallet'])
    await wallet.delete_wallet(government['wallet_config'], government['wallet_credentials'])

    print("\"Faber\" -> Close and Delete wallet")
    await wallet.close_wallet(faber['wallet'])
    await wallet.delete_wallet(faber['wallet_config'], faber['wallet_credentials'])

    print("\"Acme\" -> Close and Delete wallet")
    await wallet.close_wallet(ks['wallet'])
    await wallet.delete_wallet(ks['wallet_config'], ks['wallet_credentials'])

    print("\"GS-50\" -> Close and Delete wallet")
    await wallet.close_wallet(gs['wallet'])
    await wallet.delete_wallet(gs['wallet_config'], gs['wallet_credentials'])

    print("\"Alice\" -> Close and Delete wallet")
    await wallet.close_wallet(alice['wallet'])
    await wallet.delete_wallet(alice['wallet_config'], alice['wallet_credentials'])

    print("Close and Delete pool")
    await pool.close_pool_ledger(pool_['handle'])
    await pool.delete_pool_ledger_config(pool_['name'])

    print("Getting started -> done")


async def onboarding(_from, to):
    print("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(_from['name'], _from['name'], to['name']))
    (from_to_did, from_to_key) = await did.create_and_store_my_did(_from['wallet'], "{}")

    print("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from['name'], _from['name'], to['name']))
    await send_nym(_from['pool'], _from['wallet'], _from['did'], from_to_did, from_to_key, None)

    print("\"{}\" -> Send connection request to {} with \"{} {}\" DID and nonce"
                .format(_from['name'], to['name'], _from['name'], to['name']))
    connection_request = {
        'did': from_to_did,
        'nonce': 123456789
    }

    if 'wallet' not in to:
        print("\"{}\" -> Create wallet".format(to['name']))
        try:
            await wallet.create_wallet(to['wallet_config'], to['wallet_credentials'])
        except IndyError as ex:
            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                pass
        to['wallet'] = await wallet.open_wallet(to['wallet_config'], to['wallet_credentials'])

    print("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(to['name'], to['name'], _from['name']))
    (to_from_did, to_from_key) = await did.create_and_store_my_did(to['wallet'], "{}")

    print("\"{}\" -> Get key for did from \"{}\" connection request".format(to['name'], _from['name']))
    from_to_verkey = await did.key_for_did(_from['pool'], to['wallet'], connection_request['did'])

    print("\"{}\" -> Anoncrypt connection response for \"{}\" with \"{} {}\" DID, verkey and nonce"
                .format(to['name'], _from['name'], to['name'], _from['name']))
    to['connection_response'] = json.dumps({
        'did': to_from_did,
        'verkey': to_from_key,
        'nonce': connection_request['nonce']
    })
    to['anoncrypted_connection_response'] = \
        await crypto.anon_crypt(from_to_verkey, to['connection_response'].encode('utf-8'))

    print("\"{}\" -> Send anoncrypted connection response to \"{}\"".format(to['name'], _from['name']))
    _from['anoncrypted_connection_response'] = to['anoncrypted_connection_response']

    print("\"{}\" -> Anondecrypt connection response from \"{}\"".format(_from['name'], to['name']))
    _from['connection_response'] = \
        json.loads((await crypto.anon_decrypt(_from['wallet'], from_to_key,
                                              _from['anoncrypted_connection_response'])).decode("utf-8"))

    print("\"{}\" -> Authenticates \"{}\" by comparision of Nonce".format(_from['name'], to['name']))
    assert connection_request['nonce'] == _from['connection_response']['nonce']

    print("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from['name'], to['name'], _from['name']))
    await send_nym(_from['pool'], _from['wallet'], _from['did'], to_from_did, to_from_key, None)

    return from_to_did, from_to_key, to_from_did, to_from_key, _from['connection_response']


async def get_verinym(_from, from_to_did, from_to_key, to, to_from_did, to_from_key):
    print("\"{}\" -> Create and store in Wallet \"{}\" new DID".format(to['name'], to['name']))
    (to_did, to_key) = await did.create_and_store_my_did(to['wallet'], "{}")

    print("\"{}\" -> Authcrypt \"{} DID info\" for \"{}\"".format(to['name'], to['name'], _from['name']))
    to['did_info'] = json.dumps({
        'did': to_did,
        'verkey': to_key
    })
    to['authcrypted_did_info'] = \
        await crypto.auth_crypt(to['wallet'], to_from_key, from_to_key, to['did_info'].encode('utf-8'))

    print("\"{}\" -> Send authcrypted \"{} DID info\" to {}".format(to['name'], to['name'], _from['name']))

    print("\"{}\" -> Authdecrypted \"{} DID info\" from {}".format(_from['name'], to['name'], to['name']))
    sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info = \
        await auth_decrypt(_from['wallet'], from_to_key, to['authcrypted_did_info'])

    print("\"{}\" -> Authenticate {} by comparision of Verkeys".format(_from['name'], to['name'], ))
    assert sender_verkey == await did.key_for_did(_from['pool'], _from['wallet'], to_from_did)

    print("\"{}\" -> Send Nym to Ledger for \"{} DID\" with {} Role"
                .format(_from['name'], to['name'], to['role']))
    await send_nym(_from['pool'], _from['wallet'], _from['did'], authdecrypted_did_info['did'],
                   authdecrypted_did_info['verkey'], to['role'])

    return to_did


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def send_schema(pool_handle, wallet_handle, _did, schema):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)


async def send_cred_def(pool_handle, wallet_handle, _did, cred_def_json):
    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, cred_def_request)


async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ledger.submit_request(pool_handle, get_schema_request)
    return await ledger.parse_get_schema_response(get_schema_response)


async def get_cred_def(pool_handle, _did, cred_def_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, cred_def_id)
    get_cred_def_response = await ledger.submit_request(pool_handle, get_cred_def_request)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        print("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\"{}\" -> Get Credential Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass  # TODO Create Revocation States

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        print("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\"{}\" -> Get Credential Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass  # TODO Get Revocation Definitions and Revocation Registries

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


async def auth_decrypt(wallet_handle, key, message):
    from_verkey, decrypted_message_json = await crypto.auth_decrypt(wallet_handle, key, message)
    decrypted_message_json = decrypted_message_json.decode("utf-8")
    decrypted_message = json.loads(decrypted_message_json)
    return from_verkey, decrypted_message_json, decrypted_message


if __name__ == '__main__':
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(run())
    time.sleep(1)  # FIXME waiting for libindy thread complete
