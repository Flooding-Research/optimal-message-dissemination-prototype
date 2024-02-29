// Prototype implementation of WeakFlood2Flood protocol.
// Requires libssl-dev and libtbb-dev.
// Compile with g++ -std=c++17 -O3 wf2f.cpp -lcrypto -ltbb

#include <iostream>
#include <utility>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>
#include <string>
#include <random>
#include <chrono>
#include <execution>

#include "merklecpp/merklecpp.h"
#include "schifra/schifra_galois_field.hpp"
#include "schifra/schifra_galois_field_polynomial.hpp"
#include "schifra/schifra_sequential_root_generator_polynomial_creator.hpp"
#include "schifra/schifra_reed_solomon_encoder.hpp"
#include "schifra/schifra_reed_solomon_decoder.hpp"
#include "schifra/schifra_reed_solomon_block.hpp"

// basic configuration for experiments
const unsigned int NUM_SHARES = 10;			 // parameter mu in paper
const unsigned int MAX_DELETIONS = 2;		 // we can tolerate to loose 2 out of 10 shares
const unsigned int MSG_LENGTH = 1024 * 1024; // use 1 megabyte message

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// Accumulator based on OpenSSL SHA256 Merkle trees /////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using AccumValue = merkle::Tree::Hash;
using AccumProof = merkle::Path;

// compute SHA256 hash using OpenSSL, see https://wiki.openssl.org/index.php/EVP_Message_Digests
std::string sha256(const std::string &str)
{
	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
	EVP_DigestUpdate(mdctx, str.c_str(), str.length());
	unsigned char digest[EVP_MD_size(EVP_sha256())];
	unsigned int digest_len;
	EVP_DigestFinal_ex(mdctx, digest, &digest_len);

	EVP_MD_CTX_free(mdctx);

	// convert to hex, based on https://stackoverflow.com/a/10632725
	std::stringstream ss;
	for (unsigned int i = 0; i < digest_len; i++)
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
	}
	return ss.str();
}

// Accumulate vector of strings `messages`, sets the vector `proofs` as a proof for each
// message, and returns accumulated value (as Merkle tree root) and
AccumValue accumulate(const std::vector<std::string> &messages, std::vector<AccumProof> *proofs)
{
	merkle::Tree mt;
	for (std::string msg : messages)
		mt.insert(sha256(msg));
	AccumValue root = mt.root();

	// now finds paths and store in proofs
	proofs->clear();
	for (size_t i = mt.min_index(); i <= mt.max_index(); i++)
	{
		mt.flush_to(i);
		auto path = *mt.path(i);
		proofs->push_back(path);
	}

	return root;
}

// Verify `proof` for `message` relative to accumulated value `accum`
bool verify_accumulated(const std::string &message, const AccumProof &proof, AccumValue accum)
{
	// check that leaf of the provided path equals the hash of `message` and that the path is valid
	return proof.leaf().to_string() == sha256(message) && proof.verify(accum);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///// Error correcting code based on Reed-Solomon codes ///////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

/* Reed Solomon Code and finite field Parameters based on NUM_SHARES and MAX_DELETIONS */
const std::size_t code_length = 255;
const std::size_t bytes_per_block_share = code_length / NUM_SHARES			 // we subdivide every code word into shares
										  + (code_length % NUM_SHARES != 0); // round up
const std::size_t fec_length = MAX_DELETIONS * bytes_per_block_share;		 // how many out of the code_length symbols we can loose
const std::size_t data_length = code_length - fec_length;
const std::size_t field_descriptor = 8;
const std::size_t generator_polynomial_index = 120;
const std::size_t generator_polynomial_root_count = fec_length;

typedef schifra::reed_solomon::encoder<code_length, fec_length, data_length> encoder_t;
typedef schifra::reed_solomon::decoder<code_length, fec_length, data_length> decoder_t;
typedef schifra::reed_solomon::block<code_length, fec_length> ecc_block_t;

// encode message into NUM_SHARES number of shares
std::vector<std::string> ecc_encode(const std::string &message)
{
	/* Instantiate Finite Field and Generator Polynomials */
	const schifra::galois::field field(field_descriptor,
									   schifra::galois::primitive_polynomial_size06,
									   schifra::galois::primitive_polynomial06);

	schifra::galois::field_polynomial generator_polynomial(field);

	if (
		!schifra::make_sequential_root_generator_polynomial(
			field,
			generator_polynomial_index,
			generator_polynomial_root_count,
			generator_polynomial))
	{
		std::cout << "Error - Failed to create sequential root generator!" << std::endl;
	}

	/* Instantiate Encoder (Codec) */
	const encoder_t encoder(field, generator_polynomial);

	// initialize vector of shares
	std::vector<std::string> shares(NUM_SHARES);
	int blocks_per_share = message.length() / data_length + (message.length() % data_length != 0);
	for (unsigned int i = 0; i < NUM_SHARES; ++i)
		shares[i].resize(bytes_per_block_share * blocks_per_share);

	std::vector<size_t> indices;
	for (size_t i = 0; i * data_length < message.length(); ++i)
		indices.push_back(i);

	std::for_each(std::execution::par_unseq, indices.begin(), indices.end(), [&message, &encoder, &shares](size_t i)
				  {
		std::string msg_chunk = message.substr(i * data_length, data_length);

		/* Pad message with nulls if shorter */
		msg_chunk.resize(data_length, 0x00);

		/* Instantiate RS Block For Codec */
		ecc_block_t block;

		/* Transform message into Reed-Solomon encoded codeword */
		if (!encoder.encode(msg_chunk, block))
		{
			std::cout << "Error - Critical decoding failure! "
					  << "Msg: " << block.error_as_string() << std::endl;
		}

		// transform block to string
		std::string data;
		std::string fec;
		data.resize(data_length);
		fec.resize(fec_length);
		block.data_to_string(data);
		block.fec_to_string(fec);

		std::string block_string = data;
		block_string.resize(code_length);
		// manually add fec characters because there could be null characters
		for (size_t j = 0; j < fec_length; ++j)
			block_string[data_length + j] = fec[j];

		// split block_string into shares and append to previous shares
		for (size_t j = 0; j < code_length; ++j)
		{
			size_t share_index = j % NUM_SHARES;
			size_t offset = i * bytes_per_block_share + j / NUM_SHARES;
			shares[share_index][offset] = block_string[j];
		} });

	return shares;
}

// decode shares again, where `share_missing` indicates that this share has not been received
std::string ecc_decode(const std::vector<std::string> &shares, const std::vector<bool> &share_missing)
{
	size_t max_offset = 0;
	for (auto s : shares)
	{
		if (s.size() > max_offset)
			max_offset = s.size();
	}

	/* Instantiate Finite Field and Generator Polynomials */
	const schifra::galois::field field(field_descriptor,
									   schifra::galois::primitive_polynomial_size06,
									   schifra::galois::primitive_polynomial06);

	schifra::galois::field_polynomial generator_polynomial(field);

	if (
		!schifra::make_sequential_root_generator_polynomial(
			field,
			generator_polynomial_index,
			generator_polynomial_root_count,
			generator_polynomial))
	{
		std::cout << "Error - Failed to create sequential root generator!" << std::endl;
	}

	/* Instantiate Decoder (Codec) */
	const decoder_t decoder(field, generator_polynomial_index);

	std::vector<size_t> indices;
	for (size_t i = 0; i * bytes_per_block_share + (code_length - 1) / NUM_SHARES < max_offset; ++i)
		indices.push_back(i);

	std::vector<std::string> decoded_strings;
	decoded_strings.resize(indices.size());

	std::for_each(std::execution::par_unseq, indices.begin(), indices.end(), [&share_missing, &shares, &decoder, &decoded_strings](size_t i)
				  {
		// turn part of shares back into string
		std::string block_string;
		schifra::reed_solomon::erasure_locations_t erasure_location_list;
		block_string.resize(code_length);
		for (size_t j = 0; j < code_length; ++j)
		{
			size_t share_index = j % NUM_SHARES;
			size_t offset = i * bytes_per_block_share + j / NUM_SHARES;
			if (share_missing[share_index])
				erasure_location_list.push_back(j);
			else
				block_string[j] = shares[share_index][offset];
		}

		// turn string into block
		std::string data_string;
		std::string fec_string;
		data_string.resize(data_length);
		fec_string.resize(fec_length);
		for (size_t j = 0; j < data_length; ++j)
			data_string[j] = block_string[j];
		for (size_t j = 0; j < fec_length; ++j)
			fec_string[j] = block_string[data_length + j];

		ecc_block_t block(data_string, fec_string);

		if (!decoder.decode(block, erasure_location_list))
		{
			std::cout << "Error - Critical decoding failure!" << std::endl;
		}
		decoded_strings[i].resize(data_length);
		block.data_to_string(decoded_strings[i]); });

	std::string message;
	for (std::string decoded_string : decoded_strings)
		message += decoded_string;

	return message;
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// WeakFlood2Flood protocol /////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
struct WeakFloodPacket
{
	std::string share;
	AccumProof accum_proof;
	AccumValue accum_val;
	WeakFloodPacket(std::string s, AccumProof p, AccumValue v) : share(s), accum_proof(p), accum_val(v){};
};

// helper function, converting 32 bit integer `i` and message `msg` to a string by prepending hex encoding of `i` to `msg`
std::string pair_to_string(unsigned int i, std::string msg)
{
	std::stringstream ss;
	ss << std::hex << std::setw(8) << std::setfill('0') << i << msg;
	return ss.str();
}

// Protocol for sender. Returns vector of packets that are to be sent over independent instances of weak flooding
std::vector<WeakFloodPacket> weak_flood_2_flood_send(const std::string &message)
{
	std::vector<std::string> shares = ecc_encode(message);

	// generate vector of pairs (share[i], i) to accumulate
	std::vector<std::string> share_is;
	for (size_t i = 0; i < shares.size(); ++i)
	{
		std::string share_i = pair_to_string(i, shares[i]);
		share_is.push_back(share_i);
	}

	// accumulate
	std::vector<AccumProof> proofs;
	AccumValue accum_val = accumulate(share_is, &proofs);

	// build packets
	std::vector<WeakFloodPacket> packets;
	for (size_t i = 0; i < shares.size(); ++i)
	{
		WeakFloodPacket packet = WeakFloodPacket(shares[i], proofs[i], accum_val);
		packets.push_back(packet);
	}

	return packets;
}

// Protocol for parties receiving packets, returns sent message
std::string weak_flood_2_flood_decode_packets(const std::vector<WeakFloodPacket> &packets)
{
	std::vector<bool> share_missing(NUM_SHARES, false);
	std::vector<std::string> shares;

	// check accumulated proofs and consider share missing if proof is invalid
	for (size_t i = 0; i < packets.size(); ++i)
	{
		std::string share_i = pair_to_string(i, packets[i].share);
		if (verify_accumulated(share_i, packets[i].accum_proof, packets[i].accum_val))
		{
			shares.push_back(packets[i].share);
		}
		else
		{
			share_missing[i] = true;
			shares.push_back("");
		}
	}

	return ecc_decode(shares, share_missing);
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//// Main /////////////////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int main()
{
	// generate random message message
	std::string message;
	message.reserve(MSG_LENGTH);
	std::mt19937_64 gen{std::random_device()()};
	std::uniform_int_distribution<char> dist{32, 127};
	std::generate_n(std::back_inserter(message), MSG_LENGTH, [&]
					{ return dist(gen); });

	// Sender protocol
	std::chrono::steady_clock::time_point begin_send = std::chrono::steady_clock::now();

	std::vector<WeakFloodPacket> packets = weak_flood_2_flood_send(message);

	std::chrono::steady_clock::time_point end_send = std::chrono::steady_clock::now();
	std::cout << "Time for sender = " << std::chrono::duration_cast<std::chrono::milliseconds>(end_send - begin_send).count() << "ms" << std::endl;

	// corrupt accumulator for random packets
	// this will cause those to be discarded and the ECC must recover them
	std::vector<bool> to_corrupt(NUM_SHARES, false);
	for (unsigned int i = 0; i < MAX_DELETIONS; ++i)
		to_corrupt[i] = true;
	
	std::shuffle(to_corrupt.begin(), to_corrupt.end(), gen);

	for (size_t i = 0; i < NUM_SHARES; ++i)
	{
		if (to_corrupt[i])
			packets[i].accum_val = merkle::Tree::Hash(sha256(""));
	}

	// Receiver decoding
	std::chrono::steady_clock::time_point begin_receive = std::chrono::steady_clock::now();

	std::string received = weak_flood_2_flood_decode_packets(packets);

	std::chrono::steady_clock::time_point end_receive = std::chrono::steady_clock::now();
	std::cout << "Time for receiver = " << std::chrono::duration_cast<std::chrono::milliseconds>(end_receive - begin_receive).count() << "ms" << std::endl;

	// compare strings. Convert to C-string to get rid of potential null characters
	bool match = (std::strcmp(message.c_str(), received.c_str()) == 0);

	if (match)
		std::cout << "Received successfully." << std::endl;
	else
		std::cout << "Error: could not receive correct message." << std::endl;

	return 0;
}
