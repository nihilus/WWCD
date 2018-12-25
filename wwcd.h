#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <bytes.hpp>
#include <allins.hpp>
#include <diskio.hpp>
#include <name.hpp>
#include <pro.h>
#include <segregs.hpp>
#include <string>
#include <vector>
#include <map>
#include "capstone/capstone.h"
using namespace std;


static uint8_t capstone_icon[] = {
	0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
	0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x20, 0x08, 0x06, 0x00, 0x00, 0x00, 0x73, 0x7A, 0x7A,
	0xF4, 0x00, 0x00, 0x00, 0x06, 0x62, 0x4B, 0x47, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF9,
	0x43, 0xBB, 0x7F, 0x00, 0x00, 0x00, 0x09, 0x70, 0x48, 0x59, 0x73, 0x00, 0x00, 0x0B, 0x13, 0x00,
	0x00, 0x0B, 0x13, 0x01, 0x00, 0x9A, 0x9C, 0x18, 0x00, 0x00, 0x00, 0x07, 0x74, 0x49, 0x4D, 0x45,
	0x07, 0xDF, 0x02, 0x0B, 0x09, 0x04, 0x1D, 0x8A, 0xC6, 0x42, 0x69, 0x00, 0x00, 0x05, 0x64, 0x49,
	0x44, 0x41, 0x54, 0x58, 0xC3, 0xED, 0x97, 0x5B, 0x6C, 0x1C, 0xD5, 0x19, 0xC7, 0x7F, 0xDF, 0x39,
	0x33, 0xB3, 0xE3, 0xB5, 0x77, 0xE3, 0xC6, 0x76, 0x37, 0x2E, 0x16, 0x49, 0x94, 0x04, 0x82, 0x49,
	0x23, 0xC7, 0x8E, 0x8B, 0x02, 0x89, 0xD8, 0x20, 0x62, 0x04, 0xCD, 0x05, 0xA9, 0x5D, 0x0B, 0xD4,
	0x02, 0x2F, 0xA5, 0x48, 0xB4, 0x41, 0xAA, 0x04, 0x7D, 0xAA, 0xD4, 0xD9, 0x97, 0xE6, 0x21, 0xAD,
	0x2A, 0x81, 0x52, 0x69, 0x21, 0x08, 0x5A, 0xC4, 0x45, 0x9B, 0x04, 0x85, 0x04, 0x39, 0xA8, 0x17,
	0xB2, 0xF5, 0x43, 0x0B, 0x8D, 0xDB, 0x70, 0xC9, 0x86, 0x96, 0x4B, 0xA5, 0x92, 0xD6, 0x49, 0xD3,
	0x3A, 0x17, 0xE7, 0x82, 0x77, 0x77, 0xE6, 0x7C, 0x7D, 0x08, 0x04, 0xA8, 0x9A, 0xF8, 0x12, 0xA2,
	0xBE, 0x70, 0xA4, 0xF3, 0xF6, 0x9D, 0x6F, 0x7E, 0x73, 0x66, 0xCE, 0xFF, 0xFF, 0x3F, 0xA8, 0x2A,
	0x33, 0x99, 0x80, 0x50, 0x2D, 0x04, 0x3C, 0x38, 0xD0, 0x8C, 0x22, 0x33, 0xEE, 0x33, 0xD3, 0x85,
	0x11, 0x18, 0x36, 0x6C, 0xE8, 0xC6, 0xEF, 0xEC, 0xE3, 0xAE, 0xA5, 0xCD, 0x68, 0xD9, 0xC2, 0xF4,
	0x41, 0xA6, 0xFF, 0xE0, 0x08, 0xC3, 0xC6, 0x5B, 0x53, 0x7C, 0xED, 0xCE, 0xC5, 0xDB, 0x0D, 0x0F,
	0x55, 0xF0, 0x56, 0x5C, 0x9F, 0x62, 0x01, 0x1B, 0xBF, 0x91, 0x55, 0x10, 0x88, 0xCC, 0x74, 0xFA,
	0x19, 0xA6, 0x39, 0xA2, 0xDD, 0x7D, 0x96, 0xCC, 0xA2, 0x45, 0x6F, 0xED, 0xD8, 0x33, 0xB8, 0x02,
	0xD2, 0xC7, 0x80, 0x81, 0x14, 0xF2, 0xD5, 0x47, 0x9E, 0x6E, 0x97, 0xEF, 0xAF, 0x6F, 0x41, 0xBB,
	0x45, 0x44, 0xA6, 0xDC, 0x77, 0xCA, 0x85, 0xC5, 0xA2, 0x18, 0x11, 0xF1, 0xC9, 0x5C, 0x31, 0x77,
	0xF8, 0x47, 0x8F, 0xAF, 0xB3, 0x9C, 0x56, 0x0C, 0xD4, 0x11, 0x3D, 0x33, 0x8E, 0x76, 0x83, 0xAC,
	0x2C, 0xED, 0xEA, 0xE0, 0xEE, 0xDD, 0xA1, 0xA2, 0x6C, 0x13, 0xEC, 0x54, 0xFA, 0x7A, 0x93, 0x15,
	0x88, 0x88, 0x9C, 0x7B, 0xF5, 0x6E, 0x8F, 0x87, 0x06, 0x96, 0x1C, 0xD8, 0xFC, 0xCC, 0xDA, 0x74,
	0xF6, 0x8C, 0xAF, 0xE3, 0x61, 0x03, 0xE2, 0x4F, 0xD5, 0xAE, 0x54, 0xCC, 0xAC, 0xF2, 0x53, 0x39,
	0xE1, 0xDD, 0xC3, 0xF0, 0xBB, 0x09, 0xFD, 0x4C, 0x76, 0x60, 0x6F, 0x64, 0x79, 0x67, 0x61, 0xC0,
	0xFE, 0x65, 0x57, 0xEF, 0xDA, 0xFC, 0xD8, 0x9A, 0xA6, 0xF0, 0xA8, 0xA9, 0x8F, 0x53, 0x6F, 0x30,
	0xA1, 0x71, 0x6C, 0xD4, 0x10, 0xCA, 0xF9, 0xDA, 0x1A, 0x2C, 0xAB, 0x21, 0x03, 0xE1, 0xEF, 0xE7,
	0xB0, 0xF6, 0xBE, 0x26, 0xA1, 0x68, 0x04, 0xE4, 0x92, 0x00, 0xAA, 0xBF, 0x8D, 0x0C, 0xDB, 0xEF,
	0xB8, 0xE1, 0xD9, 0x17, 0x5E, 0xBC, 0xED, 0x3A, 0x73, 0x26, 0x9D, 0x4C, 0x04, 0xC9, 0x85, 0x6A,
	0x93, 0x1A, 0x5A, 0x03, 0xD6, 0xB7, 0xE0, 0x2F, 0xDD, 0xF7, 0x68, 0x8E, 0x25, 0x5B, 0xD2, 0x14,
	0x8B, 0x33, 0x03, 0x10, 0x8A, 0xDE, 0xE0, 0xA0, 0xD8, 0x6B, 0x0B, 0x65, 0x18, 0x3E, 0x39, 0x72,
	0xE7, 0xFA, 0xDE, 0x9D, 0x77, 0xBB, 0x96, 0xCA, 0x0E, 0xBC, 0xB1, 0x37, 0x30, 0x0D, 0x1F, 0x63,
	0x43, 0x30, 0xA3, 0x4C, 0xB8, 0x6C, 0x16, 0xD3, 0x95, 0xC2, 0xC4, 0x20, 0xFB, 0x20, 0x79, 0xC6,
	0x72, 0xE2, 0x0D, 0x72, 0x47, 0xB9, 0x6F, 0x79, 0x83, 0xEE, 0x48, 0x2A, 0x15, 0xF1, 0x2A, 0x15,
	0xF9, 0xDF, 0x9F, 0xFB, 0x82, 0x22, 0x53, 0xE8, 0x0E, 0x38, 0xA2, 0xCD, 0xE8, 0x5E, 0x8F, 0x52,
	0x9F, 0x7F, 0xEB, 0x10, 0xA9, 0x48, 0x09, 0xD0, 0xCD, 0xCD, 0x6C, 0xDA, 0x34, 0x8F, 0x55, 0x83,
	0x37, 0xAC, 0x23, 0xB8, 0xFD, 0x7E, 0xDA, 0xFA, 0xDB, 0x49, 0x77, 0x42, 0xD7, 0x6C, 0xCA, 0xB4,
	0xA0, 0x25, 0xFF, 0xC3, 0x1E, 0x66, 0xE1, 0xC3, 0xA4, 0x50, 0x15, 0x22, 0xF5, 0xE8, 0xC3, 0x07,
	0x95, 0x49, 0x75, 0xA0, 0x5C, 0xC0, 0x52, 0x28, 0xD8, 0xEB, 0x58, 0xB0, 0xFA, 0x39, 0x5A, 0x8F,
	0xFD, 0x98, 0xDC, 0x63, 0xF7, 0x32, 0xFB, 0x16, 0xE6, 0x2C, 0xEB, 0x40, 0x23, 0x33, 0x34, 0x44,
	0x8A, 0x08, 0x2F, 0x8A, 0x08, 0xFA, 0x46, 0xF0, 0xD1, 0xEF, 0x35, 0x31, 0xF2, 0x6D, 0xBF, 0xA4,
	0xF8, 0x51, 0x95, 0xE0, 0x3C, 0x40, 0xDF, 0xCA, 0x2B, 0x7B, 0xC8, 0x6C, 0xF8, 0x3A, 0x6D, 0xCF,
	0xF7, 0xD0, 0x7A, 0x9C, 0x74, 0x67, 0x2F, 0x60, 0x34, 0xC2, 0x5C, 0x14, 0xA0, 0x43, 0x69, 0x69,
	0x63, 0x4E, 0xFF, 0x1E, 0x9F, 0xB1, 0xBF, 0x1B, 0xEA, 0xEF, 0x5B, 0xEA, 0xEF, 0xE1, 0x4D, 0xEC,
	0xC2, 0x3B, 0xF9, 0x13, 0x9A, 0x87, 0x73, 0xCC, 0x5F, 0x47, 0x57, 0xD7, 0x15, 0xA8, 0xA6, 0x29,
	0x97, 0x6D, 0x09, 0x7C, 0xB4, 0x60, 0x23, 0xA2, 0x80, 0xBE, 0xEB, 0x17, 0xAC, 0x22, 0xF7, 0xAD,
	0x3C, 0x99, 0xD7, 0x1E, 0x20, 0x7D, 0xB6, 0x44, 0x50, 0xDB, 0x9A, 0x22, 0xD9, 0xE2, 0x31, 0x71,
	0x0F, 0x5F, 0x38, 0x4B, 0xE7, 0xD2, 0x5E, 0x74, 0x63, 0x4A, 0x3F, 0xA1, 0x98, 0xF2, 0xE1, 0x76,
	0x51, 0x2C, 0x8A, 0x89, 0x2A, 0x79, 0xD3, 0x59, 0xD9, 0xBF, 0x74, 0x37, 0x54, 0x66, 0x33, 0xEE,
	0x79, 0x46, 0x2D, 0x80, 0x73, 0x38, 0x30, 0x48, 0xE0, 0x7C, 0x04, 0xC6, 0x6B, 0xA9, 0xFA, 0x0E,
	0xDC, 0x3F, 0x5E, 0x27, 0xF3, 0xB3, 0x36, 0x4E, 0xFF, 0xE6, 0x15, 0xFC, 0xBB, 0x7A, 0xD0, 0x7B,
	0x97, 0x53, 0x6F, 0x4A, 0x4B, 0x4C, 0x4D, 0x89, 0x7D, 0x83, 0xF5, 0x5C, 0x20, 0x31, 0xB1, 0x13,
	0x7C, 0x11, 0xAF, 0x66, 0x5E, 0x8E, 0xB3, 0xA7, 0x9F, 0x23, 0x7B, 0x23, 0x1C, 0xAA, 0xAA, 0x8A,
	0x82, 0xEA, 0x79, 0x80, 0x25, 0x48, 0xCB, 0x3F, 0xE5, 0x9A, 0xAB, 0x7E, 0xCE, 0x5B, 0x2F, 0x2E,
	0x46, 0x66, 0x79, 0xA2, 0x17, 0x17, 0x12, 0x15, 0xF5, 0x50, 0xB3, 0x1F, 0x6B, 0xDE, 0x27, 0x69,
	0x9C, 0xFB, 0x71, 0x2E, 0x7E, 0xE4, 0xC4, 0x20, 0x6F, 0xBA, 0x96, 0xB3, 0x5B, 0x7A, 0x6E, 0xBE,
	0x29, 0xFA, 0xE9, 0xCE, 0x03, 0x51, 0x5E, 0x13, 0x39, 0xB7, 0x0E, 0xC9, 0x92, 0xED, 0xAF, 0x60,
	0x7F, 0x9D, 0x91, 0xE3, 0xC6, 0x57, 0x63, 0x8C, 0x38, 0xD1, 0x49, 0x00, 0x8C, 0x51, 0x33, 0xE2,
	0xE0, 0x88, 0x07, 0x46, 0xC1, 0x25, 0xB8, 0xC9, 0x64, 0xC7, 0x17, 0x27, 0xAF, 0xE8, 0xAC, 0x13,
	0x5B, 0xAF, 0xBD, 0xFA, 0x16, 0xAD, 0xBE, 0x7A, 0xD0, 0x43, 0xE7, 0xA5, 0x3A, 0x24, 0xE8, 0x7F,
	0x92, 0x77, 0xB7, 0xB5, 0x8A, 0xB3, 0x16, 0x0C, 0xE2, 0x98, 0x54, 0xC5, 0x44, 0x05, 0x41, 0x04,
	0x51, 0x62, 0x75, 0x6E, 0x4A, 0x82, 0xEE, 0x68, 0x28, 0xBA, 0x5C, 0x4E, 0xB6, 0x66, 0xAA, 0x07,
	0x7F, 0x25, 0x3D, 0x83, 0x03, 0xD2, 0x4E, 0xEB, 0xEA, 0x17, 0x88, 0x77, 0x7E, 0xC9, 0x3B, 0x1D,
	0x4A, 0x6C, 0x9D, 0x48, 0x22, 0x53, 0x36, 0x12, 0x83, 0xF9, 0x63, 0x22, 0x3A, 0x8A, 0x3A, 0x99,
	0xA6, 0xA9, 0xF9, 0x1E, 0xDE, 0x9F, 0xE2, 0xCC, 0x71, 0xD9, 0x43, 0x30, 0x7A, 0x0D, 0xF5, 0x56,
	0x91, 0xE9, 0x3B, 0xE3, 0xA5, 0x00, 0x9C, 0xF3, 0x19, 0xC4, 0x7C, 0xD9, 0xD4, 0xDB, 0x67, 0xE0,
	0xCA, 0x9F, 0xC9, 0x50, 0x45, 0x4D, 0xA2, 0x38, 0x23, 0xEE, 0xFF, 0x43, 0x30, 0x9D, 0x3C, 0xF0,
	0x39, 0xC0, 0xE7, 0x00, 0x97, 0x0D, 0x40, 0x80, 0x44, 0x50, 0xE4, 0x63, 0x1D, 0x57, 0xB9, 0x3C,
	0x0F, 0x13, 0x41, 0xB0, 0x98, 0xC4, 0xC7, 0x58, 0x1F, 0xDF, 0x20, 0x98, 0x61, 0xF5, 0x4E, 0x8C,
	0x3A, 0xDF, 0x39, 0x97, 0x92, 0xD0, 0xE2, 0x03, 0x18, 0x77, 0xB9, 0x0E, 0x3E, 0x6A, 0x1D, 0x1A,
	0x36, 0x44, 0x8F, 0x37, 0xC2, 0xC6, 0x09, 0x42, 0x4F, 0x50, 0x0D, 0x03, 0x69, 0x9F, 0xF7, 0x4D,
	0x92, 0xAF, 0xF4, 0xD2, 0xB8, 0x31, 0xC3, 0x99, 0xDE, 0xF9, 0xD8, 0x85, 0x39, 0x34, 0x95, 0x15,
	0x47, 0xCD, 0x47, 0x4C, 0xDD, 0x24, 0x88, 0x43, 0x54, 0x70, 0xA2, 0x60, 0x10, 0x03, 0x22, 0x8A,
	0xEE, 0x73, 0xC2, 0x11, 0xD4, 0xF1, 0x91, 0x1D, 0xAA, 0xE0, 0x8C, 0x8A, 0x38, 0x14, 0x83, 0x58,
	0x07, 0x09, 0xC6, 0x9D, 0xC2, 0x7A, 0x63, 0x58, 0xF9, 0x37, 0xFA, 0x76, 0x8C, 0xBC, 0xFA, 0x32,
	0xE1, 0xF0, 0xA1, 0x7C, 0xFF, 0x01, 0x4F, 0x61, 0x42, 0x18, 0xFB, 0xCB, 0x95, 0x65, 0xFE, 0xFA,
	0xDD, 0x02, 0x4F, 0x83, 0x5A, 0x1E, 0xD9, 0xFA, 0xC5, 0xDE, 0x07, 0x7E, 0xD0, 0xB3, 0x46, 0x6B,
	0xAB, 0x57, 0xD4, 0x1B, 0xCB, 0x7D, 0x74, 0x51, 0x4E, 0x3F, 0x68, 0x6D, 0x03, 0x1B, 0x0A, 0x26,
	0x51, 0xD4, 0x39, 0xCF, 0x89, 0x89, 0x45, 0xD1, 0xF3, 0xBE, 0xE5, 0x83, 0xA9, 0x8B, 0x26, 0x81,
	0xF3, 0x83, 0xC3, 0x48, 0x3C, 0xEE, 0xF4, 0xE4, 0x18, 0xE1, 0xC1, 0x11, 0xC2, 0xD7, 0xAB, 0xD4,
	0x5E, 0x4A, 0xCA, 0x9B, 0xF6, 0x53, 0xB8, 0xFF, 0x18, 0x90, 0x50, 0x2C, 0x2A, 0x3F, 0xE4, 0xE3,
	0x40, 0x22, 0x60, 0xCB, 0x83, 0xC2, 0x60, 0x79, 0xC8, 0x8B, 0xE4, 0x0F, 0x8D, 0xA8, 0x1A, 0x79,
	0xF9, 0xEF, 0xE0, 0x2A, 0x7B, 0xD5, 0x01, 0x29, 0x96, 0xAC, 0xBA, 0xEA, 0x8E, 0xEA, 0x9F, 0xD7,
	0xDC, 0x8C, 0x0C, 0xCC, 0xE5, 0xD4, 0xDC, 0x0E, 0x92, 0xAE, 0x59, 0x34, 0xBC, 0x11, 0xAC, 0x8E,
	0xE2, 0x68, 0x20, 0x9C, 0x22, 0x3C, 0xFC, 0x37, 0xCC, 0x7B, 0x43, 0xE8, 0x2F, 0x8F, 0x76, 0x2D,
	0xDE, 0xC3, 0xA1, 0x91, 0x03, 0x20, 0xF2, 0x44, 0x44, 0x30, 0x2F, 0x4F, 0xFC, 0x6C, 0x1E, 0x79,
	0xBB, 0x82, 0x76, 0xFC, 0x0B, 0xDD, 0x56, 0x88, 0xF4, 0x82, 0xA1, 0xF4, 0xBF, 0x03, 0xEA, 0xA7,
	0xC2, 0x6A, 0x37, 0x01, 0x5A, 0x0D, 0x72, 0xFC, 0xA2, 0x99, 0x54, 0x66, 0x6D, 0x9A, 0xF9, 0x0F,
	0x07, 0xD8, 0xDB, 0x19, 0xDD, 0x9D, 0x46, 0x0F, 0x35, 0xB1, 0x25, 0xDF, 0xF2, 0x51, 0xC6, 0xF8,
	0xE4, 0xBC, 0xE4, 0xCB, 0x29, 0x8A, 0x44, 0x8A, 0x29, 0x97, 0xB1, 0x80, 0x2D, 0x47, 0x04, 0x94,
	0xB1, 0xEC, 0xCD, 0x7B, 0x85, 0x02, 0x56, 0x4B, 0xF8, 0x94, 0x4A, 0x3E, 0x1A, 0x99, 0xE9, 0xDC,
	0x92, 0xFF, 0x03, 0x67, 0xBE, 0xAB, 0xC2, 0x06, 0x16, 0xE4, 0xCE, 0x00, 0x00, 0x00, 0x00, 0x49,
	0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
};

static int icon;

static bool use_capstone_view = false;

std::map<int, string> mem_size
{
	{ 0, "" },
	{ 1, "byte" },
	{ 2, "word" },
	{ 4, "dword" },
	{ 6, "fword" },
	{ 8, "qword" },
	{ 10, "tword" },
	{ 14, "m14" },
	{ 16, "dqword" },
	{ 28, "m28" },
	{ 32, "yword" },
	{ 64, "zword" }
};

std::map<int, string> mm0_mem_size
{
	{ 0, "" },
	{ 1, "byte" },
	{ 2, "word" },
	{ 4, "dword" },
	{ 6, "fword" },
	{ 8, "qword" },
	{ 10, "xword" },
	{ 14, "m14" },
	{ 16, "xmmword" },
	{ 28, "m28" },
	{ 32, "ymmword" },
	{ 64, "zword" }
};

#define ALIGN_SPACE 8
