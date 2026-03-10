package strategy

import (
	"fmt"
	"time"
)

// ── Fooling bitmask ───────────────────────────────────────────────────────────
// Комбинируются через | : FoolingTS | FoolingMD5Sig
// Аналог --dpi-desync-fooling=ts,md5sig,badseq,...
const (
	FoolingNone      uint32 = 0
	FoolingTS        uint32 = 1 << 0 // ts:  нулевой TCP Timestamp — сервер дропает тихо
	FoolingMD5Sig    uint32 = 1 << 1 // md5sig: TCP MD5 Signature option (RFC 2385)
	FoolingBadSum    uint32 = 1 << 2 // badsum: corrupt TCP checksum
	FoolingBadSeq    uint32 = 1 << 3 // badseq: seq += BadSeqIncrement (вне окна у сервера)
	FoolingDataNoAck uint32 = 1 << 4 // datanoack: убрать флаг ACK
)

// ── SplitMode ─────────────────────────────────────────────────────────────────

type SplitMode int

const (
	SplitNone          SplitMode = iota
	SplitCustom                  // произвольные позиции из SplitPositions
	SplitSeqOvl                  // multisplit: seqovl-пакет + сегменты (основная техника zapret)
	SplitFakedSplit              // fakedsplit: fake-пакет + сплит в FakedSplitPos
	SplitMultiDisorder           // multidisorder: disorder в нескольких позициях
)

func (s SplitMode) String() string {
	switch s {
	case SplitNone:
		return "none"
	case SplitCustom:
		return "custom"
	case SplitSeqOvl:
		return "seqovl"
	case SplitFakedSplit:
		return "fakedsplit"
	case SplitMultiDisorder:
		return "multidisorder"
	default:
		return fmt.Sprintf("SplitMode(%d)", int(s))
	}
}

// ── DisorderMode ──────────────────────────────────────────────────────────────

type DisorderMode int

const (
	DisorderNone          DisorderMode = iota
	DisorderTTLZero                    // decoy TTL=disorder_ttl
	DisorderOutOfBand                  // OOB: bad seq + low TTL
	DisorderBadSeq                     // только bad seq
	DisorderFakedDisorder              // fake-пакет + реальные сегменты
)

func (d DisorderMode) String() string {
	switch d {
	case DisorderNone:
		return "none"
	case DisorderTTLZero:
		return "ttl-zero"
	case DisorderOutOfBand:
		return "oob"
	case DisorderBadSeq:
		return "bad-seq"
	case DisorderFakedDisorder:
		return "faked-disorder"
	default:
		return fmt.Sprintf("DisorderMode(%d)", int(d))
	}
}

// ── HTTPModMode ───────────────────────────────────────────────────────────────

type HTTPModMode int

const (
	HTTPModNone       HTTPModMode = iota
	HTTPModHostCase               // MiXeD CaSe Host:
	HTTPModExtraSpace             // доп. пробел после метода
	HTTPModDotAtEnd               // точка в конце Host: example.com.
	HTTPModAll
)

func (h HTTPModMode) String() string {
	switch h {
	case HTTPModNone:
		return "none"
	case HTTPModHostCase:
		return "host-case"
	case HTTPModExtraSpace:
		return "extra-space"
	case HTTPModDotAtEnd:
		return "dot-at-end"
	case HTTPModAll:
		return "all"
	default:
		return "unknown"
	}
}

// ── Strategy ──────────────────────────────────────────────────────────────────

type Strategy struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`

	// ── Применение ───────────────────────────────────────────────────────────
	ApplyToHTTP bool `json:"apply_to_http"`
	ApplyToTLS  bool `json:"apply_to_tls"`
	ApplyToQUIC bool `json:"apply_to_quic"`
	// AnyProtocol: применять к любому протоколу (--dpi-desync-any-protocol=1)
	AnyProtocol bool `json:"any_protocol"`
	// Cutoff: остановить после N первых data-пакетов потока (0=без ограничений)
	// --dpi-desync-cutoff=n2/n3/n4/n5
	Cutoff int `json:"cutoff"`
	// IPIDZero: установить IP ID = 0 (--ip-id=zero, Google/Cloudflare)
	IPIDZero bool `json:"ip_id_zero"`

	// ── Split / SeqOvl ───────────────────────────────────────────────────────
	SplitMode      SplitMode `json:"split_mode"`
	SplitPositions []int     `json:"split_positions"`  // позиции (байты от начала payload)
	SplitSNIOffset bool      `json:"split_sni_offset"` // позиции относительно SNI
	// SplitPosMidSLD: дополнительная позиция в середине SLD (midsld)
	SplitPosMidSLD bool `json:"split_pos_midsld"`
	// SplitPosSNIExt: дополнительная позиция после SNI-extension (sniext+1)
	SplitPosSNIExt bool `json:"split_pos_sniext"`

	// SeqOvl: отправить пакет с seq = real_seq - SeqOvlLen и данными из SeqOvlPatternFile
	// перед реальными сегментами. DPI читает «старые» данные и теряет контекст.
	// --dpi-desync=multisplit --dpi-desync-split-seqovl=N --dpi-desync-split-seqovl-pattern=file
	SeqOvlLen         int    `json:"seqovl_len"`          // длина перекрытия (568, 652, 664, 679, 681)
	SeqOvlPatternFile string `json:"seqovl_pattern_file"` // имя .bin файла (без пути)
	SeqOvlPatternData []byte `json:"-"`                   // загружается при старте

	// FakedSplit: отправить fake-пакет, затем сплит в позиции FakedSplitPos.
	// --dpi-desync=fake,fakedsplit --dpi-desync-fakedsplit-pattern=0x00
	FakedSplit        bool `json:"faked_split"`
	FakedSplitPos     int  `json:"faked_split_pos"`     // позиция разбивки (байт от начала payload)
	FakedSplitPattern byte `json:"faked_split_pattern"` // байт-заполнитель (обычно 0x00)

	// ── Disorder ─────────────────────────────────────────────────────────────
	DisorderMode    DisorderMode `json:"disorder_mode"`
	DisorderPos     []int        `json:"disorder_pos"`
	DisorderTTL     int          `json:"disorder_ttl"`
	DisorderRepeats int          `json:"disorder_repeats"`

	// SynData: отправить SYN с fake payload перед реальным SYN.
	// Самый агрессивный режим -- DPI теряет начало потока.
	// --dpi-desync=syndata
	SynData bool `json:"syn_data"`

	// MultiDisorder: disorder в нескольких позициях одновременно.
	// --dpi-desync=multidisorder  (часто идёт с syndata)
	MultiDisorder bool `json:"multi_disorder"`

	// ── Fake packets ─────────────────────────────────────────────────────────
	// FakeRepeats: сколько fake-пакетов отправить (--dpi-desync-repeats=N)
	FakeRepeats int `json:"fake_repeats"`

	// FakeTTL: TTL fake-пакета (должен "умереть" до сервера, но дойти до DPI)
	FakeTTL int `json:"fake_ttl"`

	// Fooling: битовая маска FoolingTS|FoolingBadSeq|FoolingMD5Sig|...
	// Определяет КАК fake-пакет невидим для сервера.
	// --dpi-desync-fooling=ts,badseq,md5sig
	Fooling uint32 `json:"fooling"`

	// BadSeqIncrement: на сколько сдвинуть SEQ в fake при FoolingBadSeq
	// --dpi-desync-badseq-increment=N (2, 1000, 10000000)
	BadSeqIncrement int64 `json:"badseq_increment"`

	// FakeTLSFiles: список .bin файлов для fake TLS (циклически ротируются между повторами)
	// --dpi-desync-fake-tls=file1 --dpi-desync-fake-tls=file2 ...
	FakeTLSFiles     []string `json:"fake_tls_files"`
	FakeTLSFilesData [][]byte `json:"-"` // загружается при старте

	// FakeTLSNullBytes: использовать 4 нулевых байта как fake TLS
	// --dpi-desync-fake-tls=0x00000000
	FakeTLSNullBytes bool `json:"fake_tls_null_bytes"`

	// FakeTLSPrevPacket: использовать предыдущий ClientHello как fake
	// --dpi-desync-fake-tls=^!
	FakeTLSPrevPacket bool `json:"fake_tls_prev_packet"`

	// FakeTLSMod: модификация fake TLS на лету (не нужен файл)
	// --dpi-desync-fake-tls-mod=rnd,dupsid,sni=domain
	// Если FakeTLSModNone=true: --dpi-desync-fake-tls-mod=none (отключить автогенерацию)
	FakeTLSModNone   bool   `json:"fake_tls_mod_none"`   // none: не модифицировать
	FakeTLSModRnd    bool   `json:"fake_tls_mod_rnd"`    // rnd: рандомизировать поля
	FakeTLSModDupSID bool   `json:"fake_tls_mod_dupsid"` // dupsid: дублировать session ID
	FakeTLSModSNI    string `json:"fake_tls_mod_sni"`    // sni=domain: подменить SNI

	// FakeHTTPFile: .bin файл для fake HTTP пакета
	// --dpi-desync-fake-http=file
	FakeHTTPFile     string `json:"fake_http_file"`
	FakeHTTPFileData []byte `json:"-"`

	// FakeQUICFile: .bin файл для fake QUIC Initial (UDP 443)
	// --dpi-desync-fake-quic=file
	FakeQUICFile     string `json:"fake_quic_file"`
	FakeQUICFileData []byte `json:"-"`
	FakeQUICRepeats  int    `json:"fake_quic_repeats"` // повторов (6 или 11)

	// FakeUnknownUDPFile: fake для неизвестного UDP (игровой трафик)
	// --dpi-desync-fake-unknown-udp=file
	FakeUnknownUDPFile     string `json:"fake_unknown_udp_file"`
	FakeUnknownUDPFileData []byte `json:"-"`

	// ── HostFakeSplit ─────────────────────────────────────────────────────────
	// Подменяет Host: заголовок в fake-пакете и разбивает поток внутри Host.
	// --dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=host=domain,altorder=N
	HostFakeSplit         bool   `json:"host_fake_split"`
	HostFakeSplitHost     string `json:"host_fake_split_host"`     // заменить Host: на этот
	HostFakeSplitAltOrder int    `json:"host_fake_split_altorder"` // altorder=0..3

	// ── HTTP ─────────────────────────────────────────────────────────────────
	HTTPModMode HTTPModMode `json:"http_mod_mode"`
	HostCase    bool        `json:"host_case"`
	ExtraSpace  bool        `json:"extra_space"`
	DotAtEnd    bool        `json:"dot_at_end"`

	// ── TLS record split ─────────────────────────────────────────────────────
	// Обычно не нужен — используй TCP split вместо него.
	TLSRecordSplit bool `json:"tls_record_split"`
	TLSRecordSize  int  `json:"tls_record_size"`

	// ── Прочее ───────────────────────────────────────────────────────────────
	WindowSize int `json:"window_size"`

	// Метаданные
	Priority               int       `json:"priority"`
	SuccessCount           int       `json:"success_count"`
	FailCount              int       `json:"fail_count"`
	AvgResponseMs          int64     `json:"avg_response_ms"`
	ModifyFirstDataPackets int       `json:"modify_first_data_packets"`
	ApplyToPacketTypes     []string  `json:"apply_to_packet_types"`
	LastUsed               time.Time `json:"last_used,omitempty"`

	// ── Устаревшие / legacy поля (совместимость с существующим JSON) ──────────
	DisorderPos2         []int  `json:"disorder_pos2,omitempty"`
	FakeDsPattern        []byte `json:"fake_ds_pattern,omitempty"`
	FakeDsMod            int    `json:"fake_ds_mod,omitempty"`
	SeqOvlPos            int    `json:"seqovl_pos,omitempty"`
	UdplenIncrement      int    `json:"udplen_increment,omitempty"`
	QUICttl              int    `json:"quic_ttl,omitempty"`
	Repeats              int    `json:"repeats,omitempty"`
	FakeMode             int    `json:"fake_mode,omitempty"` // legacy: заменён на Fooling
	FakePos              int    `json:"fake_pos,omitempty"`
	SplitSNIOffsetLegacy bool   `json:"split_sni_offset_legacy,omitempty"`
	FakeQUIC             bool   `json:"fake_quic,omitempty"`
	IPID                 int    `json:"ip_id,omitempty"`
	TTL                  int    `json:"ttl,omitempty"`
}

// ── Методы ───────────────────────────────────────────────────────────────────

// HasFooling проверяет наличие конкретного флага
func (s *Strategy) HasFooling(flag uint32) bool { return s.Fooling&flag != 0 }

// NeedsQUICFake — нужен fake QUIC Initial
func (s *Strategy) NeedsQUICFake() bool {
	return s.ApplyToQUIC && s.FakeQUICFile != "" && len(s.FakeQUICFileData) > 0
}

// NeedsSeqOvl — используется multisplit с seqovl
func (s *Strategy) NeedsSeqOvl() bool {
	return s.SplitMode == SplitSeqOvl && s.SeqOvlLen > 0
}

// NeedsSynData — используется syndata техника
func (s *Strategy) NeedsSynData() bool { return s.SynData }

// NeedsMultiDisorder — используется multidisorder
func (s *Strategy) NeedsMultiDisorder() bool { return s.MultiDisorder }

// FakeTLSData возвращает данные для fake TLS по индексу (с ротацией)
func (s *Strategy) FakeTLSData(idx int) []byte {
	if len(s.FakeTLSFilesData) == 0 {
		return nil
	}
	return s.FakeTLSFilesData[idx%len(s.FakeTLSFilesData)]
}

// Clone создаёт полную независимую копию (все slice-поля явно копируются).
func (s *Strategy) Clone() *Strategy {
	clone := *s
	clone.SplitPositions = cloneInts(s.SplitPositions)
	clone.DisorderPos = cloneInts(s.DisorderPos)
	clone.ApplyToPacketTypes = cloneStrings(s.ApplyToPacketTypes)
	clone.FakeTLSFiles = cloneStrings(s.FakeTLSFiles)
	clone.DisorderPos2 = cloneInts(s.DisorderPos2)
	if s.FakeDsPattern != nil {
		clone.FakeDsPattern = make([]byte, len(s.FakeDsPattern))
		copy(clone.FakeDsPattern, s.FakeDsPattern)
	}
	if s.SeqOvlPatternData != nil {
		clone.SeqOvlPatternData = make([]byte, len(s.SeqOvlPatternData))
		copy(clone.SeqOvlPatternData, s.SeqOvlPatternData)
	}
	if s.FakeHTTPFileData != nil {
		clone.FakeHTTPFileData = make([]byte, len(s.FakeHTTPFileData))
		copy(clone.FakeHTTPFileData, s.FakeHTTPFileData)
	}
	if s.FakeQUICFileData != nil {
		clone.FakeQUICFileData = make([]byte, len(s.FakeQUICFileData))
		copy(clone.FakeQUICFileData, s.FakeQUICFileData)
	}
	if s.FakeUnknownUDPFileData != nil {
		clone.FakeUnknownUDPFileData = make([]byte, len(s.FakeUnknownUDPFileData))
		copy(clone.FakeUnknownUDPFileData, s.FakeUnknownUDPFileData)
	}
	// FakeTLSFilesData: slice of immutable byte slices — копируем только заголовок
	if s.FakeTLSFilesData != nil {
		clone.FakeTLSFilesData = make([][]byte, len(s.FakeTLSFilesData))
		copy(clone.FakeTLSFilesData, s.FakeTLSFilesData)
	}
	return &clone
}

func (s *Strategy) String() string {
	return fmt.Sprintf("%s(split=%v,disorder=%v,fooling=0x%x,syndata=%v)",
		s.Name, s.SplitMode, s.DisorderMode, s.Fooling, s.SynData)
}

// ── Вспомогательные типы ──────────────────────────────────────────────────────

type StrategyFilter struct {
	Protocol  string
	Ports     []int
	Hostnames []string
	IPRanges  []string
	Country   string
	ASN       int
}

type StrategyResult struct {
	StrategyID   int
	Success      bool
	ResponseTime time.Duration
	BytesSent    int
	PacketsSent  int
	Error        string
	Timestamp    time.Time
}

func cloneInts(src []int) []int {
	if src == nil {
		return nil
	}
	dst := make([]int, len(src))
	copy(dst, src)
	return dst
}

func cloneStrings(src []string) []string {
	if src == nil {
		return nil
	}
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}
