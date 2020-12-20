#ifndef GW_VALIDATOR_H_
#define GW_VALIDATOR_H_

#include "ckb_syscalls.h"
#include "common.h"

#define MAX_BUF_SIZE 65536

typedef struct {
  gw_context_t gw_ctx;
  uint32_t account_count;
  gw_state_t *kv_state;
  /* SMT proof */
  uint8_t *kv_state_proof;
  size_t kv_state_proof_size;
  /* To proof the block is in the chain */
  uint8_t *block_proof;
  size_t block_proof_size;
  uint8_t *tx_proof;
  size_t *tx_proof_size;
  /* The script of entrance account */
  uint8_t *entrance_account_script;
  size_t entrance_account_script_size;
  uint32_t entrance_account_id;
} gw_verification_context_t;

int sys_load(void *ctx, uint32_t account_id, const uint8_t key[GW_KEY_BYTES],
             uint8_t value[GW_VALUE_BYTES]) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  gw_verification_context_t *verify_ctx = (gw_verification_context_t *)ctx;
  uint8_t raw_key[GW_KEY_BYTES] = {0};
  gw_build_account_key(account_id, key, raw_key);
  return gw_state_fetch(verify_ctx->kv_state, raw_key, value);
}
int sys_store(void *ctx, uint32_t account_id, const uint8_t key[GW_KEY_BYTES],
              const uint8_t value[GW_VALUE_BYTES]) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  gw_verification_context_t *verify_ctx = (gw_verification_context_t *)ctx;
  uint8_t raw_key[GW_KEY_BYTES];
  gw_build_account_key(account_id, key, raw_key);
  return gw_state_insert(verify_ctx->kv_state, raw_key, value);
}

int sys_load_nonce(void *ctx, uint32_t account_id, uint8_t value[GW_VALUE_BYTES]) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  gw_verification_context_t *verify_ctx = (gw_verification_context_t *)ctx;
  uint8_t key[32];
  gw_build_nonce_key(account_id, key);
  return gw_state_fetch(verify_ctx->kv_state, key, value);
}

/* set call return data */
int sys_set_program_return_data(void *ctx, uint8_t *data, uint32_t len) {
  /* FIXME */
  return -1;
}

/* Get account id by account script_hash */
int sys_get_account_id_by_script_hash(void *ctx, uint8_t script_hash[32],
                                      uint32_t *account_id) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  gw_verification_context_t *verify_ctx = (gw_verification_context_t *)ctx;
  uint8_t raw_key[32];
  uint8_t value[32];
  gw_build_script_hash_to_account_id_key(script_hash, raw_key);
  int ret = gw_state_fetch(verify_ctx->kv_state, raw_key, value);
  if (ret != 0) {
    return ret;
  }
  for (int i = 4; i < 32; i++) {
    if (value[i] != 0) {
      ckb_debug("Invalid account id value");
      return -1;
    }
  }
  *account_id = *((uint32_t *)value);
  return 0;
}

/* Get account script_hash by account id */
int sys_get_script_hash_by_account_id(void *ctx, uint32_t account_id,
                                      uint8_t script_hash[32]) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  gw_verification_context_t *verify_ctx = (gw_verification_context_t *)ctx;
  uint8_t raw_key[32];
  gw_build_account_field_key(account_id, GW_ACCOUNT_SCRIPT_HASH, raw_key);
  return gw_state_fetch(verify_ctx->kv_state, raw_key, script_hash);
}

/* Get account script by account id */
int sys_get_account_script(void *ctx, uint32_t account_id, uint32_t *len,
                         uint32_t offset, uint8_t *script) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  int ret;
  gw_verification_context_t *verify_ctx = (gw_verification_context_t *)ctx;

  if (verify_ctx->entrance_account_id == account_id) {
    /* verify the script hash */
    uint8_t script_hash[32];
    ret = sys_get_script_hash_by_account_id(ctx, account_id, script_hash);
    if (ret != 0) {
      return ret;
    }
    uint8_t calculated_script_hash[32];
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, 32);
    blake2b_update(&blake2b_ctx,
                   verify_ctx->entrance_account_script,
                   verify_ctx->entrance_account_script_size);
    blake2b_final(&blake2b_ctx, calculated_script_hash, 32);

    if (memcmp(script_hash, calculated_script_hash, 32) != 0) {
      ckb_debug("verify entrance account script hash failed");
      return -1;
    }

    /* return account script */
    size_t new_len;
    size_t data_len = verify_ctx->entrance_account_script_size;
    if (offset >= data_len) {
      new_len = 0;
    } else if ((offset + *len) > data_len) {
      new_len = data_len - offset;
    } else {
      new_len = *len;
    }
    if (new_len > 0) {
      memcpy(script, verify_ctx->entrance_account_script + offset, new_len);
    }
    return 0;
  } else {
    ckb_debug("account script not found for given account id");
    return -1;
  }
}
/* Store data by data hash */
int sys_store_data(void *ctx,
                 uint32_t data_len,
                 uint8_t *data) {
  /* TODO: any verification ? */
  /* do nothing for now */
  return 0;
}
/* Load data by data hash */
int sys_load_data(void *ctx, uint8_t data_hash[32],
                 uint32_t *len, uint32_t offset, uint8_t *data) {
  int ret;
  size_t index = 0;
  uint64_t hash_len = 32;
  uint8_t hash[32];
  while (1) {
    ret = ckb_load_cell_by_field(hash, &hash_len, 0, index, CKB_SOURCE_CELL_DEP, CKB_CELL_FIELD_DATA_HASH);
    if (ret == CKB_ITEM_MISSING) {
      ckb_debug("not found cell data by data hash");
      return -1;
    } else if (ret == CKB_SUCCESS) {
      if (memcmp(hash, data_hash, 32) == 0) {
        uint64_t data_len = (uint64_t)*len;
        ret = ckb_load_cell_data(data, &data_len, offset, index, CKB_SOURCE_CELL_DEP);
        if (ret != CKB_SUCCESS) {
          ckb_debug("load cell data failed");
          return -1;
        }
        *len = (uint32_t)data_len;
        return 0;
      }
    } else {
      ckb_debug("load cell data hash failed");
      return -1;
    }
    index += 1;
  }
  /* dead code */
  return -1;
}

int _sys_load_l2transaction(void *addr, uint64_t *len) {
  /* FIXME */
  return -1;
}

int _sys_load_block_info(void *addr, uint64_t *len) {
  /* FIXME */
  return -1;
}

int sys_create(void *ctx, uint8_t *script, uint32_t script_len,
               uint32_t *account_id) {
  if (ctx == NULL) {
    return GW_ERROR_INVALID_CONTEXT;
  }
  gw_verification_context_t *verify_ctx = (gw_verification_context_t *)ctx;
  int ret;
  uint32_t id = verify_ctx->account_count;

  uint8_t nonce_key[32];
  uint8_t nonce_value[32];
  gw_build_account_field_key(id, GW_ACCOUNT_NONCE, nonce_key);
  memset(nonce_value, 0, 32);
  ret = gw_state_insert(verify_ctx->kv_state, nonce_key, nonce_value);
  if (ret != 0) {
    return -1;
  }

  uint8_t script_hash[32];
  uint8_t script_hash_key[32];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, 32);
  blake2b_update(&blake2b_ctx, script, script_len);
  blake2b_final(&blake2b_ctx, script_hash, 32);
  gw_build_account_field_key(id, GW_ACCOUNT_SCRIPT_HASH, script_hash_key);
  ret = gw_state_insert(verify_ctx->kv_state, script_hash_key, script_hash);
  if (ret != 0) {
    return -1;
  }

  uint8_t hash_to_id_key[32];
  uint8_t hash_to_id_value[32];
  gw_build_script_hash_to_account_id_key(script_hash, hash_to_id_key);
  memcpy(hash_to_id_value, (uint8_t *)(&id), 4);
  ret = gw_state_insert(verify_ctx->kv_state, hash_to_id_key, hash_to_id_value);
  if (ret != 0) {
    return -1;
  }

  /* TODO: how to verify new_scripts */

  verify_ctx->account_count += 1;

  return 0;
}

int sys_log(void *ctx, uint32_t account_id, uint32_t data_length,
            const uint8_t *data) {
  /* do nothing */
  return 0;
}

int gw_context_init(gw_verification_context_t *context) {
  gw_context_t *gw_ctx = &context->gw_ctx;
  memset(gw_ctx, 0, sizeof(gw_context_t));
  /* setup syscalls */
  gw_ctx->sys_load = sys_load;
  gw_ctx->sys_load_nonce = sys_load_nonce;
  gw_ctx->sys_store = sys_store;
  gw_ctx->sys_set_program_return_data = sys_set_program_return_data;
  gw_ctx->sys_create = sys_create;
  gw_ctx->sys_get_account_id_by_script_hash =
      sys_get_account_id_by_script_hash;
  gw_ctx->sys_get_script_hash_by_account_id =
      sys_get_script_hash_by_account_id;
  gw_ctx->sys_get_account_script = sys_get_account_script;
  gw_ctx->sys_store_data = sys_store_data;
  gw_ctx->sys_load_data = sys_load_data;
  gw_ctx->sys_log = sys_log;

  /* initialize context */
  // 1. load transaction
  uint8_t buf[MAX_BUF_SIZE] = {0};
  uint64_t len = MAX_BUF_SIZE;
  int ret = _sys_load_l2transaction(buf, &len);
  if (ret != 0) {
    return ret;
  }
  if (len > MAX_BUF_SIZE) {
    return GW_ERROR_INVALID_DATA;
  }

  mol_seg_t l2transaction_seg;
  l2transaction_seg.ptr = buf;
  l2transaction_seg.size = len;
  ret = gw_parse_transaction_context(&gw_ctx->transaction_context,
                                     &l2transaction_seg);
  if (ret != 0) {
    return ret;
  }

  // 2. load block info
  len = MAX_BUF_SIZE;
  ret = _sys_load_block_info(buf, &len);
  if (ret != 0) {
    return ret;
  }
  if (len > MAX_BUF_SIZE) {
    return GW_ERROR_INVALID_DATA;
  }

  mol_seg_t block_info_seg;
  block_info_seg.ptr = buf;
  block_info_seg.size = len;
  ret = gw_parse_block_info(&gw_ctx->block_info, &block_info_seg);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

#endif
