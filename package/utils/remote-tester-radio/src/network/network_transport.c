/* SPDX-License-Identifier: GPL-2.0-only */
#include "network.h"

#include <errno.h>
#include <limits.h>
#include <string.h>

#include <zlib.h>

#define QUEUE_RECORD_HEADER 3U
#define FRAGMENT_HEADER_BYTES 18U

static void put_u16(uint8_t *out, uint16_t value)
{
	out[0] = (uint8_t)value;
	out[1] = (uint8_t)(value >> 8);
}

static uint16_t get_u16(const uint8_t *in)
{
	return (uint16_t)in[0] | ((uint16_t)in[1] << 8);
}

static void put_u32(uint8_t *out, uint32_t value)
{
	out[0] = (uint8_t)value;
	out[1] = (uint8_t)(value >> 8);
	out[2] = (uint8_t)(value >> 16);
	out[3] = (uint8_t)(value >> 24);
}

static uint32_t get_u32(const uint8_t *in)
{
	return (uint32_t)in[0] | ((uint32_t)in[1] << 8) |
		((uint32_t)in[2] << 16) | ((uint32_t)in[3] << 24);
}

static bool valid_destination(uint8_t destination)
{
	return destination <= NETWORK_MAX_ID;
}

static void ring_write(struct network_queue *queue, const uint8_t *input, size_t length)
{
	size_t first = queue->capacity - queue->tail;
	if (first > length)
		first = length;
	memcpy(queue->storage + queue->tail, input, first);
	if (length > first)
		memcpy(queue->storage, input + first, length - first);
	queue->tail = (queue->tail + length) % queue->capacity;
	queue->used += length;
}

static void ring_peek(const struct network_queue *queue, uint8_t *output, size_t length)
{
	size_t first = queue->capacity - queue->head;
	if (first > length)
		first = length;
	memcpy(output, queue->storage + queue->head, first);
	if (length > first)
		memcpy(output + first, queue->storage, length - first);
}

static void ring_peek_at(const struct network_queue *queue, size_t offset,
	uint8_t *output, size_t length)
{
	size_t start = (queue->head + offset) % queue->capacity;
	size_t first = queue->capacity - start;
	if (first > length)
		first = length;
	memcpy(output, queue->storage + start, first);
	if (length > first)
		memcpy(output + first, queue->storage, length - first);
}

int network_queue_init(struct network_queue *queue, uint8_t *storage, size_t capacity)
{
	if (!queue || !storage || capacity < QUEUE_RECORD_HEADER + 1U ||
	    capacity > NETWORK_QUEUE_MAX_BYTES)
		return -EINVAL;
	memset(queue, 0, sizeof(*queue));
	queue->storage = storage;
	queue->capacity = capacity;
	return 0;
}

int network_queue_push(struct network_queue *queue, uint8_t destination,
	const uint8_t *bytes, size_t length)
{
	uint8_t header[QUEUE_RECORD_HEADER];
	if (!queue || !queue->storage || !valid_destination(destination) || !bytes || !length)
		return -EINVAL;
	if (length > UINT16_MAX)
		return -EMSGSIZE;
	if (QUEUE_RECORD_HEADER + length > queue->capacity - queue->used)
		return -ENOSPC;
	header[0] = destination;
	put_u16(header + 1, (uint16_t)length);
	ring_write(queue, header, sizeof(header));
	ring_write(queue, bytes, length);
	queue->bytes_by_node[destination] += length;
	return 0;
}

int network_queue_peek(const struct network_queue *queue, uint8_t *destination,
	uint8_t *bytes, size_t output_capacity, size_t *length)
{
	uint8_t header[QUEUE_RECORD_HEADER];
	uint16_t item_length;
	if (!queue || !queue->storage || !destination || !bytes || !length)
		return -EINVAL;
	if (queue->used < QUEUE_RECORD_HEADER)
		return -EAGAIN;
	ring_peek(queue, header, sizeof(header));
	item_length = get_u16(header + 1);
	if (!item_length || QUEUE_RECORD_HEADER + item_length > queue->used ||
	    !valid_destination(header[0]))
		return -EBADMSG;
	*length = item_length;
	if (output_capacity < item_length)
		return -ENOSPC;
	*destination = header[0];
	ring_peek_at(queue, QUEUE_RECORD_HEADER, bytes, item_length);
	return 0;
}

int network_queue_drop_front(struct network_queue *queue, uint8_t *destination,
	size_t *length)
{
	uint8_t header[QUEUE_RECORD_HEADER];
	uint16_t item_length;
	uint8_t item_destination;
	if (!queue || !queue->storage)
		return -EINVAL;
	if (queue->used < QUEUE_RECORD_HEADER)
		return -EAGAIN;
	ring_peek(queue, header, sizeof(header));
	item_destination = header[0];
	item_length = get_u16(header + 1);
	if (!item_length || QUEUE_RECORD_HEADER + item_length > queue->used ||
	    !valid_destination(item_destination) ||
	    queue->bytes_by_node[item_destination] < item_length)
		return -EBADMSG;
	queue->head = (queue->head + QUEUE_RECORD_HEADER + item_length) % queue->capacity;
	queue->used -= QUEUE_RECORD_HEADER + item_length;
	queue->bytes_by_node[item_destination] -= item_length;
	if (destination)
		*destination = item_destination;
	if (length)
		*length = item_length;
	return 0;
}

int network_queue_pop(struct network_queue *queue, uint8_t *destination,
	uint8_t *bytes, size_t output_capacity, size_t *length)
{
	int error;
	if (!destination)
		return -EINVAL;
	error = network_queue_peek(queue, destination, bytes, output_capacity, length);
	if (error)
		return error;
	return network_queue_drop_front(queue, NULL, NULL);
}

size_t network_queue_demand_bytes(const struct network_queue *queue, uint8_t destination)
{
	if (!queue || !queue->storage || !valid_destination(destination))
		return 0;
	return queue->bytes_by_node[destination];
}

int network_block_compress(const uint8_t *input, size_t input_length,
	uint8_t *output, size_t output_capacity, size_t *output_length)
{
	z_stream stream;
	int result;
	if (!input || !input_length || input_length > NETWORK_MAX_SERIAL_BLOCK || !output ||
	    !output_length || output_capacity > UINT_MAX || input_length > UINT_MAX)
		return -EINVAL;
	memset(&stream, 0, sizeof(stream));
	result = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS,
		8, Z_DEFAULT_STRATEGY);
	if (result != Z_OK)
		return -EIO;
	stream.next_in = (Bytef *)(uintptr_t)input;
	stream.avail_in = (uInt)input_length;
	stream.next_out = output;
	stream.avail_out = (uInt)output_capacity;
	result = deflate(&stream, Z_FINISH);
	if (result != Z_STREAM_END) {
		(void)deflateEnd(&stream);
		return result == Z_BUF_ERROR ? -ENOSPC : -EIO;
	}
	*output_length = stream.total_out;
	(void)deflateEnd(&stream);
	return 0;
}

int network_block_decompress(const uint8_t *input, size_t input_length,
	size_t expected_output_length, uint8_t *output, size_t output_capacity,
	size_t *output_length)
{
	z_stream stream;
	int result;
	if (!input || !input_length || input_length > NETWORK_MAX_COMPRESSED_BLOCK ||
	    !expected_output_length || expected_output_length > NETWORK_MAX_SERIAL_BLOCK ||
	    !output || !output_length || output_capacity < expected_output_length ||
	    output_capacity > UINT_MAX || input_length > UINT_MAX)
		return -EINVAL;
	memset(&stream, 0, sizeof(stream));
	result = inflateInit2(&stream, -MAX_WBITS);
	if (result != Z_OK)
		return -EIO;
	stream.next_in = (Bytef *)(uintptr_t)input;
	stream.avail_in = (uInt)input_length;
	stream.next_out = output;
	stream.avail_out = (uInt)expected_output_length;
	result = inflate(&stream, Z_FINISH);
	if (result != Z_STREAM_END || stream.total_out != expected_output_length || stream.avail_in != 0) {
		(void)inflateEnd(&stream);
		return -EBADMSG;
	}
	*output_length = stream.total_out;
	(void)inflateEnd(&stream);
	return 0;
}

int network_block_encode(const uint8_t *input, size_t input_length, uint8_t *output,
	size_t output_capacity, size_t *output_length, uint8_t *codec)
{
	uint8_t compressed[NETWORK_MAX_COMPRESSED_BLOCK];
	size_t compressed_length = 0;
	int result;
	if (!input || !input_length || input_length > NETWORK_MAX_SERIAL_BLOCK || !output ||
	    !output_length || !codec)
		return -EINVAL;
	result = network_block_compress(input, input_length, compressed, sizeof(compressed),
		&compressed_length);
	if (!result && compressed_length < input_length) {
		if (output_capacity < compressed_length)
			return -ENOSPC;
		memcpy(output, compressed, compressed_length);
		*output_length = compressed_length;
		*codec = NETWORK_CODEC_DEFLATE;
		return 0;
	}
	if (output_capacity < input_length)
		return -ENOSPC;
	memcpy(output, input, input_length);
	*output_length = input_length;
	*codec = NETWORK_CODEC_RAW;
	return 0;
}

int network_block_fragment(uint32_t stream_id, uint16_t block_id, uint32_t raw_offset,
	uint16_t raw_length, uint8_t codec, const uint8_t *encoded, size_t encoded_length,
	struct network_fragment *fragments, size_t fragment_capacity, size_t *fragment_count)
{
	size_t count, i;
	if (!encoded || !encoded_length || encoded_length > NETWORK_MAX_COMPRESSED_BLOCK ||
	    !raw_length || raw_length > NETWORK_MAX_SERIAL_BLOCK ||
	    raw_offset > UINT32_MAX - raw_length || !fragments || !fragment_count ||
	    (codec != NETWORK_CODEC_RAW && codec != NETWORK_CODEC_DEFLATE) ||
	    (codec == NETWORK_CODEC_RAW && encoded_length != raw_length))
		return -EINVAL;
	count = (encoded_length + NETWORK_FRAGMENT_DATA_BYTES - 1U) / NETWORK_FRAGMENT_DATA_BYTES;
	if (count > NETWORK_MAX_FRAGMENTS || fragment_capacity < count)
		return -ENOSPC;
	for (i = 0; i < count; i++) {
		struct network_fragment *fragment = &fragments[i];
		size_t offset = i * NETWORK_FRAGMENT_DATA_BYTES;
		size_t data_length = encoded_length - offset;
		if (data_length > NETWORK_FRAGMENT_DATA_BYTES)
			data_length = NETWORK_FRAGMENT_DATA_BYTES;
		memset(fragment, 0, sizeof(*fragment));
		fragment->stream_id = stream_id;
		fragment->block_id = block_id;
		fragment->raw_offset = raw_offset;
		fragment->index = (uint8_t)i;
		fragment->count = (uint8_t)count;
		fragment->codec = codec;
		fragment->raw_length = raw_length;
		fragment->compressed_length = (uint16_t)encoded_length;
		fragment->data_length = (uint16_t)data_length;
		memcpy(fragment->data, encoded + offset, data_length);
	}
	*fragment_count = count;
	return 0;
}

void network_stream_builder_init(struct network_stream_builder *builder, uint32_t stream_id,
	uint16_t first_block_id, uint32_t first_raw_offset)
{
	if (!builder)
		return;
	memset(builder, 0, sizeof(*builder));
	builder->stream_id = stream_id;
	builder->next_block_id = first_block_id;
	builder->next_raw_offset = first_raw_offset;
}

int network_stream_builder_append(struct network_stream_builder *builder,
	const uint8_t *input, size_t input_length, uint64_t now_ms, size_t *consumed)
{
	size_t available, amount;
	if (!builder || !consumed || (input_length && !input) || !builder->stream_id)
		return -EINVAL;
	*consumed = 0;
	if (!input_length)
		return 0;
	if (builder->next_raw_offset > UINT32_MAX - builder->pending_length)
		return -EOVERFLOW;
	available = NETWORK_MAX_SERIAL_BLOCK - builder->pending_length;
	amount = input_length < available ? input_length : available;
	if (builder->next_raw_offset + builder->pending_length > UINT32_MAX - amount)
		return -EOVERFLOW;
	memcpy(builder->pending + builder->pending_length, input, amount);
	builder->pending_length += amount;
	builder->last_append_ms = now_ms;
	*consumed = amount;
	return 0;
}

bool network_stream_builder_flush_due(const struct network_stream_builder *builder,
	uint64_t now_ms)
{
	if (!builder || !builder->pending_length)
		return false;
	if (builder->pending_length == NETWORK_MAX_SERIAL_BLOCK)
		return true;
	return now_ms >= builder->last_append_ms &&
		now_ms - builder->last_append_ms >= NETWORK_BLOCK_FLUSH_MS;
}

int network_stream_builder_take(struct network_stream_builder *builder, uint64_t now_ms,
	bool force, struct network_fragment *fragments, size_t fragment_capacity,
	size_t *fragment_count)
{
	uint8_t encoded[NETWORK_MAX_COMPRESSED_BLOCK];
	size_t encoded_length = 0, count = 0;
	uint8_t codec = NETWORK_CODEC_RAW;
	int result;
	if (!builder || !fragments || !fragment_count || !builder->stream_id)
		return -EINVAL;
	*fragment_count = 0;
	if (!builder->pending_length)
		return 0;
	if (!force && !network_stream_builder_flush_due(builder, now_ms))
		return 0;
	result = network_block_encode(builder->pending, builder->pending_length, encoded,
		sizeof(encoded), &encoded_length, &codec);
	if (result)
		return result;
	result = network_block_fragment(builder->stream_id, builder->next_block_id,
		builder->next_raw_offset, (uint16_t)builder->pending_length, codec, encoded,
		encoded_length, fragments, fragment_capacity, &count);
	if (result)
		return result;
	builder->next_raw_offset += (uint32_t)builder->pending_length;
	builder->next_block_id++;
	builder->pending_length = 0;
	builder->last_append_ms = 0;
	*fragment_count = count;
	return 1;
}

static int validate_fragment(const struct network_fragment *fragment)
{
	size_t expected_count, expected_length;
	if (!fragment || !fragment->count || fragment->count > NETWORK_MAX_FRAGMENTS ||
	    fragment->index >= fragment->count || !fragment->raw_length ||
	    fragment->raw_length > NETWORK_MAX_SERIAL_BLOCK ||
	    fragment->raw_offset > UINT32_MAX - fragment->raw_length ||
	    !fragment->compressed_length ||
	    fragment->compressed_length > NETWORK_MAX_COMPRESSED_BLOCK ||
	    (fragment->codec != NETWORK_CODEC_RAW && fragment->codec != NETWORK_CODEC_DEFLATE) ||
	    (fragment->codec == NETWORK_CODEC_RAW && fragment->compressed_length != fragment->raw_length))
		return -EINVAL;
	expected_count = (fragment->compressed_length + NETWORK_FRAGMENT_DATA_BYTES - 1U) /
		NETWORK_FRAGMENT_DATA_BYTES;
	expected_length = fragment->compressed_length -
		(size_t)fragment->index * NETWORK_FRAGMENT_DATA_BYTES;
	if (expected_length > NETWORK_FRAGMENT_DATA_BYTES)
		expected_length = NETWORK_FRAGMENT_DATA_BYTES;
	if (fragment->count != expected_count || !expected_length ||
	    fragment->data_length != expected_length)
		return -EBADMSG;
	return 0;
}

int network_fragment_pack(const struct network_fragment *fragment, uint8_t *output,
	size_t output_capacity, size_t *output_length)
{
	int result = validate_fragment(fragment);
	if (result || !output || !output_length)
		return result ? result : -EINVAL;
	if (output_capacity < FRAGMENT_HEADER_BYTES + fragment->data_length ||
	    FRAGMENT_HEADER_BYTES + fragment->data_length > NETWORK_FRAME_MAX_PAYLOAD)
		return -EMSGSIZE;
	put_u32(output, fragment->stream_id);
	put_u16(output + 4, fragment->block_id);
	put_u32(output + 6, fragment->raw_offset);
	put_u16(output + 10, fragment->raw_length);
	put_u16(output + 12, fragment->compressed_length);
	output[14] = fragment->index;
	output[15] = fragment->count;
	output[16] = fragment->codec;
	output[17] = (uint8_t)fragment->data_length;
	memcpy(output + FRAGMENT_HEADER_BYTES, fragment->data, fragment->data_length);
	*output_length = FRAGMENT_HEADER_BYTES + fragment->data_length;
	return 0;
}

int network_fragment_unpack(const uint8_t *input, size_t input_length,
	struct network_fragment *fragment)
{
	int result;
	if (!input || !fragment || input_length < FRAGMENT_HEADER_BYTES ||
	    input_length > FRAGMENT_HEADER_BYTES + NETWORK_FRAGMENT_DATA_BYTES)
		return -EINVAL;
	memset(fragment, 0, sizeof(*fragment));
	fragment->stream_id = get_u32(input);
	fragment->block_id = get_u16(input + 4);
	fragment->raw_offset = get_u32(input + 6);
	fragment->raw_length = get_u16(input + 10);
	fragment->compressed_length = get_u16(input + 12);
	fragment->index = input[14];
	fragment->count = input[15];
	fragment->codec = input[16];
	fragment->data_length = input[17];
	if (input_length != FRAGMENT_HEADER_BYTES + fragment->data_length ||
	    fragment->data_length > NETWORK_FRAGMENT_DATA_BYTES)
		return -EBADMSG;
	memcpy(fragment->data, input + FRAGMENT_HEADER_BYTES, fragment->data_length);
	result = validate_fragment(fragment);
	return result;
}

void network_reassembler_init(struct network_reassembler *reassembler)
{
	if (reassembler)
		memset(reassembler, 0, sizeof(*reassembler));
}

static uint32_t complete_bitmap(uint8_t count)
{
	return count == 32U ? UINT32_MAX : ((1U << count) - 1U);
}

int network_reassembler_add(struct network_reassembler *reassembler, uint8_t source,
	const struct network_fragment *fragment, uint8_t *raw_output, size_t output_capacity,
	size_t *raw_length, uint32_t *raw_offset, uint32_t *received_bitmap,
	uint32_t *missing_bitmap)
{
	struct network_reassembly_slot *slot;
	uint32_t mask, bit;
	size_t offset;
	int result = validate_fragment(fragment);
	if (!reassembler || source > NETWORK_MAX_ID ||
	    !raw_output || !raw_length)
		return -EINVAL;
	if (result)
		return result;
	slot = &reassembler->by_source[source];
	if (slot->active && (slot->stream_id != fragment->stream_id ||
	    slot->block_id != fragment->block_id || slot->raw_offset != fragment->raw_offset ||
	    slot->raw_length != fragment->raw_length ||
	    slot->compressed_length != fragment->compressed_length ||
	    slot->count != fragment->count || slot->codec != fragment->codec))
		return -EBUSY;
	if (!slot->active) {
		memset(slot, 0, sizeof(*slot));
		slot->active = true;
		slot->stream_id = fragment->stream_id;
		slot->block_id = fragment->block_id;
		slot->raw_offset = fragment->raw_offset;
		slot->raw_length = fragment->raw_length;
		slot->compressed_length = fragment->compressed_length;
		slot->count = fragment->count;
		slot->codec = fragment->codec;
	}
	bit = 1U << fragment->index;
	offset = (size_t)fragment->index * NETWORK_FRAGMENT_DATA_BYTES;
	if (slot->received_bitmap & bit) {
		if (memcmp(slot->compressed + offset, fragment->data, fragment->data_length))
			return -EBADMSG;
	} else {
		memcpy(slot->compressed + offset, fragment->data, fragment->data_length);
		slot->received_bitmap |= bit;
	}
	mask = complete_bitmap(slot->count);
	if (received_bitmap)
		*received_bitmap = slot->received_bitmap;
	if (missing_bitmap)
		*missing_bitmap = mask & ~slot->received_bitmap;
	if (slot->received_bitmap != mask)
		return 0;
	if (output_capacity < slot->raw_length)
		return -ENOSPC;
	if (slot->codec == NETWORK_CODEC_RAW) {
		memcpy(raw_output, slot->compressed, slot->raw_length);
		*raw_length = slot->raw_length;
	} else {
		result = network_block_decompress(slot->compressed, slot->compressed_length,
			slot->raw_length, raw_output, output_capacity, raw_length);
		if (result)
			return result;
	}
	if (raw_offset)
		*raw_offset = slot->raw_offset;
	slot->active = false;
	return 1;
}
