/* SPDX-License-Identifier: GPL-2.0-only */
#include "radiolib_backend.h"
#include "radio_linux.h"

#include "vendor/RadioLib/src/Hal.h"
#include "vendor/RadioLib/src/Module.h"
#include "vendor/RadioLib/src/modules/SX126x/SX1262.h"

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <gpiod.h>
#include <linux/spi/spidev.h>
#include <new>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {

enum : uint32_t {
	PIN_CS = 1,
	PIN_DIO1,
	PIN_RESET,
	PIN_BUSY,
	PIN_TXEN,
	PIN_RXEN,
};

constexpr uint64_t RADIO_BUSY_TIMEOUT_US = 500000U;

class LinuxRadioHal final : public RadioLibHal {
public:
	explicit LinuxRadioHal(struct radio_linux *radio) :
		RadioLibHal(0, 1, 0, 1, 1, 2), radio_(radio) {}

	void pinMode(uint32_t, uint32_t) override {}

	void digitalWrite(uint32_t pin, uint32_t value) override
	{
		struct gpiod_line *line = nullptr;
		switch (pin) {
		case PIN_CS:
			/* spidev asserts chip select for each SPI_IOC_MESSAGE. */
			return;
		case PIN_RESET:
			line = radio_->reset;
			break;
		case PIN_TXEN:
			line = radio_->txen;
			break;
		case PIN_RXEN:
			line = radio_->rxen;
			break;
		default:
			return;
		}
		if (!line) {
			setError(-EINVAL);
			return;
		}
		if (gpiod_line_set_value(line, value ? 1 : 0))
			setError(errno ? -errno : -EIO);
	}

	uint32_t digitalRead(uint32_t pin) override
	{
		struct gpiod_line *line = pin == PIN_BUSY ? radio_->busy :
			(pin == PIN_DIO1 ? radio_->dio1 : nullptr);
		int value;
		if (!line) {
			setError(-EINVAL);
			return 0;
		}
		value = gpiod_line_get_value(line);
		if (value < 0) {
			setError(errno ? -errno : -EIO);
			return 0;
		}
		if (pin == PIN_BUSY) {
			if (value) {
				uint64_t now = nowUs();
				if (!busy_since_us_)
					busy_since_us_ = now;
				else if (now - busy_since_us_ >= RADIO_BUSY_TIMEOUT_US) {
					busy_since_us_ = 0;
					setError(-ETIMEDOUT);
					return 0;
				}
			} else {
				busy_since_us_ = 0;
			}
		}
		return static_cast<uint32_t>(value);
	}

	/* DIO1 edge delivery is owned by libgpiod and the daemon's event loop. */
	void attachInterrupt(uint32_t, void (*)(void), uint32_t) override {}
	void detachInterrupt(uint32_t) override {}

	void delay(RadioLibTime_t ms) override { sleepFor(static_cast<uint64_t>(ms) * 1000U); }
	void delayMicroseconds(RadioLibTime_t us) override { sleepFor(static_cast<uint64_t>(us)); }
	RadioLibTime_t millis() override { return static_cast<RadioLibTime_t>(nowUs() / 1000U); }
	RadioLibTime_t micros() override { return static_cast<RadioLibTime_t>(nowUs()); }
	long pulseIn(uint32_t, uint32_t, RadioLibTime_t) override { return 0; }
	void spiBegin() override {}
	void spiBeginTransaction() override {}

	void spiTransfer(uint8_t *out, size_t len, uint8_t *in) override
	{
		struct spi_ioc_transfer transfer = {};
		int transferred;
		if (!out || !in || len > UINT32_MAX) {
			setError(-EINVAL);
			return;
		}
		std::memset(in, 0, len);
		if (error_)
			return;
		transfer.tx_buf = reinterpret_cast<uintptr_t>(out);
		transfer.rx_buf = reinterpret_cast<uintptr_t>(in);
		transfer.len = static_cast<uint32_t>(len);
		transfer.speed_hz = radio_->spi_hz;
		transfer.bits_per_word = 8;
		transferred = ioctl(radio_->spi_fd, SPI_IOC_MESSAGE(1), &transfer);
		if (transferred < 0)
			setError(errno ? -errno : -EIO);
		else if (static_cast<size_t>(transferred) != len)
			setError(-EIO);
	}

	void spiEndTransaction() override {}
	void spiEnd() override {}
	void yield() override { sleepFor(1000); }

	int error() const { return error_; }
	void clearError()
	{
		error_ = 0;
		busy_since_us_ = 0;
	}

private:
	struct radio_linux *radio_;
	int error_ = 0;
	uint64_t busy_since_us_ = 0;

	void setError(int error)
	{
		if (!error_)
			error_ = error;
	}

	static uint64_t nowUs()
	{
		struct timespec ts = {};
		if (clock_gettime(CLOCK_MONOTONIC, &ts))
			return 0;
		return static_cast<uint64_t>(ts.tv_sec) * 1000000U +
			static_cast<uint64_t>(ts.tv_nsec / 1000L);
	}

	static void sleepFor(uint64_t us)
	{
		struct timespec delay = {
			static_cast<time_t>(us / 1000000U),
			static_cast<long>((us % 1000000U) * 1000U),
		};
		while (nanosleep(&delay, &delay) && errno == EINTR) {}
	}
};

class LinuxSX1262 final : public SX1262 {
public:
	explicit LinuxSX1262(Module *module) : SX1262(module) {}

	int readDiagnostics(uint8_t *chipMode, uint8_t *commandStatus, uint16_t *syncWord)
	{
		uint8_t status = getStatus();
		uint8_t sync[2] = {};
		int16_t result = readRegister(0x0740, sync, sizeof(sync));
		if (result != RADIOLIB_ERR_NONE)
			return -EIO;
		if (chipMode)
			*chipMode = (status >> 4) & 0x07;
		if (commandStatus)
			*commandStatus = (status >> 1) & 0x07;
		if (syncWord)
			*syncWord = static_cast<uint16_t>((static_cast<uint16_t>(sync[0]) << 8) | sync[1]);
		return 0;
	}
};

} // namespace

struct radiolib_backend {
	explicit radiolib_backend(struct radio_linux *radio) : hal(radio), module(&hal, PIN_CS, PIN_DIO1, PIN_RESET, PIN_BUSY), sx1262(&module) {}

	LinuxRadioHal hal;
	Module module;
	LinuxSX1262 sx1262;
};

namespace {

static radiolib_backend *backend(struct radio_linux *radio)
{
	return radio ? radio->backend : nullptr;
}

static int result_code(radiolib_backend *b, int16_t result)
{
	return b->hal.error() ? b->hal.error() : (result == RADIOLIB_ERR_NONE ? 0 : -EIO);
}

static uint8_t sync_value(uint16_t word)
{
	uint8_t high = static_cast<uint8_t>(word >> 8);
	uint8_t low = static_cast<uint8_t>(word);
	return static_cast<uint8_t>((high & 0xf0) | ((low & 0xf0) >> 4));
}

static uint8_t sync_control(uint16_t word)
{
	uint8_t high = static_cast<uint8_t>(word >> 8);
	uint8_t low = static_cast<uint8_t>(word);
	return static_cast<uint8_t>(((high & 0x0f) << 4) | (low & 0x0f));
}

static int8_t as_db(float value)
{
	if (!std::isfinite(value))
		return 0;
	return static_cast<int8_t>(std::max(-128L, std::min(127L, std::lround(value))));
}

} // namespace

extern "C" int radiolib_backend_create(struct radio_linux *radio)
{
	static const uint32_t pins[Module::RFSWITCH_MAX_PINS] = {
		PIN_TXEN, PIN_RXEN, RADIOLIB_NC, RADIOLIB_NC, RADIOLIB_NC,
	};
	static const Module::RfSwitchMode_t switchModes[] = {
		{Module::MODE_IDLE, {0, 0}},
		{Module::MODE_RX, {1, 0}},
		{Module::MODE_TX, {0, 1}},
		END_OF_MODE_TABLE,
	};
	if (!radio || radio->backend)
		return -EINVAL;
	radiolib_backend *b = new (std::nothrow) radiolib_backend(radio);
	if (!b)
		return -ENOMEM;
	b->module.setRfSwitchTable(pins, switchModes);
	radio->backend = b;
	return 0;
}

extern "C" void radiolib_backend_destroy(struct radio_linux *radio)
{
	if (!radio || !radio->backend)
		return;
	delete radio->backend;
	radio->backend = nullptr;
}

extern "C" int radiolib_backend_configure(struct radio_linux *radio, const struct radio_config *config)
{
	radiolib_backend *b = backend(radio);
	int16_t result;
	if (!b || !config)
		return -EINVAL;
	b->hal.clearError();
	result = b->sx1262.begin(static_cast<float>(config->frequency_mhz),
		static_cast<float>(config->bandwidth_khz), static_cast<uint8_t>(config->spreading_factor),
		static_cast<uint8_t>(config->coding_rate), sync_value(static_cast<uint16_t>(config->sync_word)),
		-9, 8, 3.3f, false);
	if (result_code(b, result))
		return result_code(b, result);
	b->hal.clearError();
	result = b->sx1262.setDio2AsRfSwitch(false);
	if (result_code(b, result))
		return result_code(b, result);
	b->hal.clearError();
	result = b->sx1262.setSyncWord(sync_value(static_cast<uint16_t>(config->sync_word)),
		sync_control(static_cast<uint16_t>(config->sync_word)));
	if (result_code(b, result))
		return result_code(b, result);
	return 0;
}

extern "C" int radiolib_backend_set_frequency(struct radio_linux *radio, uint32_t frequency_mhz)
{
	radiolib_backend *b = backend(radio);
	if (!b)
		return -ENODEV;
	b->hal.clearError();
	return result_code(b, b->sx1262.setFrequency(static_cast<float>(frequency_mhz)));
}

extern "C" int radiolib_backend_start_receive(struct radio_linux *radio, uint8_t payload_len, bool continuous)
{
	radiolib_backend *b = backend(radio);
	if (!b)
		return -ENODEV;
	b->hal.clearError();
	uint32_t timeout = continuous ? RADIOLIB_SX126X_RX_TIMEOUT_INF : 0;
	int16_t result = b->sx1262.startReceive(timeout, RADIOLIB_IRQ_RX_DEFAULT_FLAGS,
		RADIOLIB_IRQ_RX_DEFAULT_MASK, payload_len);
	return result_code(b, result);
}

extern "C" int radiolib_backend_start_transmit(struct radio_linux *radio, const uint8_t *data, size_t len)
{
	radiolib_backend *b = backend(radio);
	if (!b || !data || !len || len > 240)
		return -EINVAL;
	b->hal.clearError();
	return result_code(b, b->sx1262.startTransmit(data, len));
}

extern "C" int radiolib_backend_start_cad(struct radio_linux *radio)
{
	radiolib_backend *b = backend(radio);
	if (!b)
		return -ENODEV;
	b->hal.clearError();
	return result_code(b, b->sx1262.startChannelScan());
}

extern "C" int radiolib_backend_handle_irq(struct radio_linux *radio, uint16_t *irq)
{
	radiolib_backend *b = backend(radio);
	uint32_t flags;
	int16_t result;
	size_t payloadLen;
	if (!b)
		return -ENODEV;
	b->hal.clearError();
	flags = b->sx1262.getIrqFlags();
	if (b->hal.error())
		return b->hal.error();
	radio->last_irq = static_cast<uint16_t>(flags);
	if (irq)
		*irq = radio->last_irq;
	radio->cad_result_valid = (flags & RADIOLIB_SX126X_IRQ_CAD_DONE) != 0;
	radio->last_cad_busy = (flags & RADIOLIB_SX126X_IRQ_CAD_DETECTED) != 0;
	if (flags & RADIOLIB_SX126X_IRQ_RX_DONE) {
		b->hal.clearError();
		radio->last_rssi_dbm = as_db(b->sx1262.getRSSI(true));
		radio->last_snr_db = as_db(b->sx1262.getSNR());
		if (b->hal.error())
			return b->hal.error();
		payloadLen = b->sx1262.getPacketLength(true);
		if (payloadLen > sizeof(radio->last_rx)) {
			radio->last_rx_len = 0;
			b->hal.clearError();
			result = b->sx1262.readData(radio->last_rx, sizeof(radio->last_rx));
			if (b->hal.error())
				return b->hal.error();
			if (result != RADIOLIB_ERR_NONE && result != RADIOLIB_ERR_CRC_MISMATCH)
				return -EIO;
			return -EOVERFLOW;
		}
		radio->last_rx_len = static_cast<uint8_t>(payloadLen);
		if (payloadLen) {
			b->hal.clearError();
			result = b->sx1262.readData(radio->last_rx, payloadLen);
			if (b->hal.error())
				return b->hal.error();
			if (result != RADIOLIB_ERR_NONE && result != RADIOLIB_ERR_CRC_MISMATCH)
				return -EIO;
		} else {
			b->hal.clearError();
			result = b->sx1262.clearIrqFlags(flags);
			if (result_code(b, result))
				return result_code(b, result);
		}
	} else {
		b->hal.clearError();
		result = b->sx1262.clearIrqFlags(flags);
		if (result_code(b, result))
			return result_code(b, result);
	}
	return 0;
}

extern "C" int radiolib_backend_sample_rssi(struct radio_linux *radio, int16_t *rssi_dbm)
{
	radiolib_backend *b = backend(radio);
	if (!b || !rssi_dbm)
		return -EINVAL;
	b->hal.clearError();
	*rssi_dbm = as_db(b->sx1262.getRSSI(false));
	return b->hal.error();
}

extern "C" int radiolib_backend_diagnostics(struct radio_linux *radio, uint8_t *chip_mode,
	uint8_t *command_status, uint16_t *sync_word)
{
	radiolib_backend *b = backend(radio);
	if (!b)
		return -ENODEV;
	b->hal.clearError();
	int result = b->sx1262.readDiagnostics(chip_mode, command_status, sync_word);
	return b->hal.error() ? b->hal.error() : result;
}

extern "C" int radiolib_backend_standby_rc(struct radio_linux *radio)
{
	radiolib_backend *b = backend(radio);
	if (!b)
		return -ENODEV;
	b->hal.clearError();
	return result_code(b, b->sx1262.standby());
}
