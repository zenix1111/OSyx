/*
 * OSyx compatibility layer for OpenBSD network drivers: the kernel
 * interfaces declared in ../include/osyx_bsd.h. See that file for the
 * execution model (one big lock held by the Rust side around every call
 * into this code, polled interrupt handlers).
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include <osyx_bsd.h>
#include <sys/queue.h>
#include <net/if_media.h>
#include <dev/mii/mii.h>
#include <dev/mii/miivar.h>
#include <dev/pci/pcireg.h>

/* ---- libc ----------------------------------------------------------------- */

/* Normally provided by Rust's compiler_builtins; weak in case they are not. */
__attribute__((weak)) void *memcpy(void *d, const void *s, size_t n)
{
	uint8_t *dp = d;
	const uint8_t *sp = s;
	while (n--) *dp++ = *sp++;
	return d;
}

__attribute__((weak)) void *memmove(void *d, const void *s, size_t n)
{
	uint8_t *dp = d;
	const uint8_t *sp = s;
	if (dp < sp) {
		while (n--) *dp++ = *sp++;
	} else {
		while (n--) dp[n] = sp[n];
	}
	return d;
}

__attribute__((weak)) void *memset(void *d, int c, size_t n)
{
	uint8_t *dp = d;
	while (n--) *dp++ = (uint8_t)c;
	return d;
}

__attribute__((weak)) int memcmp(const void *a, const void *b, size_t n)
{
	const uint8_t *x = a, *y = b;
	for (; n; n--, x++, y++)
		if (*x != *y)
			return *x - *y;
	return 0;
}

size_t strlen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

int strcmp(const char *a, const char *b)
{
	while (*a && *a == *b) { a++; b++; }
	return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
	for (; n > 0; n--, a++, b++) {
		if (*a != *b || *a == 0)
			return (unsigned char)*a - (unsigned char)*b;
	}
	return 0;
}

size_t strlcpy(char *d, const char *s, size_t n)
{
	size_t len = strlen(s);
	if (n > 0) {
		size_t c = len < n - 1 ? len : n - 1;
		memcpy(d, s, c);
		d[c] = 0;
	}
	return len;
}

size_t strlcat(char *d, const char *s, size_t n)
{
	size_t dl = strlen(d);
	if (dl >= n)
		return dl + strlen(s);
	return dl + strlcpy(d + dl, s, n - dl);
}

/* ---- formatted output ----------------------------------------------------------- */

struct out { char *buf; size_t cap; size_t len; };

static void put(struct out *o, char c)
{
	if (o->len + 1 < o->cap)
		o->buf[o->len] = c;
	o->len++;
}

static void put_num(struct out *o, uint64_t v, int base, int upper, int width, int zero, int neg)
{
	char tmp[24];
	const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
	int n = 0;
	do { tmp[n++] = digits[v % base]; v /= base; } while (v);
	int len = n + (neg ? 1 : 0);
	if (neg && zero)
		put(o, '-');
	for (; width > len; width--)
		put(o, zero ? '0' : ' ');
	if (neg && !zero)
		put(o, '-');
	while (n)
		put(o, tmp[--n]);
}

int vsnprintf(char *buf, size_t cap, const char *fmt, va_list ap)
{
	struct out o = { buf, cap, 0 };
	for (; *fmt; fmt++) {
		if (*fmt != '%') { put(&o, *fmt); continue; }
		fmt++;
		int zero = 0, width = 0, lng = 0, left = 0;
		while (*fmt == '0' || *fmt == '-' || *fmt == '#' || *fmt == ' ' || *fmt == '+') {
			if (*fmt == '0') zero = 1;
			if (*fmt == '-') left = 1;
			fmt++;
		}
		if (*fmt == '*') { width = va_arg(ap, int); fmt++; }
		while (*fmt >= '0' && *fmt <= '9')
			width = width * 10 + (*fmt++ - '0');
		if (*fmt == '.') {
			fmt++;
			if (*fmt == '*') { (void)va_arg(ap, int); fmt++; }
			while (*fmt >= '0' && *fmt <= '9') fmt++;
		}
		while (*fmt == 'l' || *fmt == 'h' || *fmt == 'z' || *fmt == 'q' || *fmt == 't' || *fmt == 'j') {
			if (*fmt == 'l' || *fmt == 'z' || *fmt == 'q' || *fmt == 't' || *fmt == 'j') lng++;
			fmt++;
		}
		(void)left;
		switch (*fmt) {
		case 'd': case 'i': {
			int64_t v = lng ? va_arg(ap, int64_t) : va_arg(ap, int);
			put_num(&o, v < 0 ? (uint64_t)-v : (uint64_t)v, 10, 0, width, zero, v < 0);
			break;
		}
		case 'u': case 'x': case 'X': case 'o': {
			uint64_t v = lng ? va_arg(ap, uint64_t) : va_arg(ap, unsigned int);
			int base = *fmt == 'u' ? 10 : *fmt == 'o' ? 8 : 16;
			put_num(&o, v, base, *fmt == 'X', width, zero, 0);
			break;
		}
		case 'p':
			put(&o, '0'); put(&o, 'x');
			put_num(&o, (uint64_t)va_arg(ap, void *), 16, 0, 0, 0, 0);
			break;
		case 'c':
			put(&o, (char)va_arg(ap, int));
			break;
		case 's': {
			const char *s = va_arg(ap, const char *);
			if (s == NULL) s = "(null)";
			size_t n = strlen(s);
			for (; width > (int)n; width--) put(&o, ' ');
			while (*s) put(&o, *s++);
			break;
		}
		case 'b': {
			/* OpenBSD %b: value, then "\base" followed by "\bitNAME" pairs. */
			unsigned int v = va_arg(ap, unsigned int);
			const char *bits = va_arg(ap, const char *);
			int base = *bits++;
			put_num(&o, v, base, 0, 0, 0, 0);
			int any = 0;
			while (*bits) {
				int bit = *bits++;
				if (v & (1U << (bit - 1))) {
					put(&o, any ? ',' : '<');
					any = 1;
					while (*bits > ' ') put(&o, *bits++);
				} else {
					while (*bits > ' ') bits++;
				}
			}
			if (any) put(&o, '>');
			break;
		}
		case '%':
			put(&o, '%');
			break;
		default:
			put(&o, '%');
			if (*fmt) put(&o, *fmt);
			else fmt--;
		}
	}
	if (cap > 0)
		buf[o.len < cap ? o.len : cap - 1] = 0;
	return (int)o.len;
}

int snprintf(char *buf, size_t cap, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(buf, cap, fmt, ap);
	va_end(ap);
	return n;
}

/* Kernel messages are collected into lines. */
static char line[256];
static size_t line_len;

int vprintf(const char *fmt, va_list ap)
{
	char tmp[256];
	int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
	for (int i = 0; i < n && i < (int)sizeof(tmp) - 1; i++) {
		if (tmp[i] == '\n' || line_len == sizeof(line) - 1) {
			osyx_bsd_log(line, line_len);
			line_len = 0;
			if (tmp[i] == '\n')
				continue;
		}
		line[line_len++] = tmp[i];
	}
	return n;
}

int printf(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	int n = vprintf(fmt, ap);
	va_end(ap);
	return n;
}

void panic(const char *fmt, ...)
{
	char tmp[200];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(tmp, sizeof(tmp), fmt, ap);
	va_end(ap);
	osyx_bsd_panic(tmp);
}

/* ---- memory ------------------------------------------------------------------ */

/* A size header keeps free(9) independent of the size argument. */
#define HDR 16

void *malloc(size_t size, int type, int flags)
{
	(void)type;
	uint8_t *p = osyx_bsd_alloc(size + HDR, HDR);
	if (p == NULL) {
		if (flags & M_WAITOK && !(flags & M_CANFAIL))
			panic("malloc: out of memory (%zu bytes)", size);
		return NULL;
	}
	*(size_t *)p = size;
	if (flags & M_ZERO)
		memset(p + HDR, 0, size);
	return p + HDR;
}

void *mallocarray(size_t n, size_t size, int type, int flags)
{
	if (size && n > (size_t)-1 / size)
		return NULL;
	return malloc(n * size, type, flags);
}

void free(void *ptr, int type, size_t size)
{
	(void)type; (void)size;
	if (ptr == NULL)
		return;
	uint8_t *p = (uint8_t *)ptr - HDR;
	osyx_bsd_free(p, *(size_t *)p + HDR, HDR);
}

int copyout(const void *k, void *u, size_t n) { memcpy(u, k, n); return 0; }
int copyin(const void *u, void *k, size_t n) { memcpy(k, u, n); return 0; }

/* ---- time --------------------------------------------------------------------- */

int hz = 1000;
int tick = 1000;
volatile int ticks;
char *hw_vendor, *hw_prod;

void osyx_bsd_hda_kick(void);
void osyx_bsd_hda_regs(uint64_t va);

void delay(int us)
{
	if (us > 0)
		osyx_bsd_delay_us((uint64_t)us);
	osyx_bsd_hda_kick();
}

static struct timeout *timeouts;

void timeout_set(struct timeout *to, void (*f)(void *), void *arg)
{
	to->to_func = f;
	to->to_arg = arg;
	to->to_flags = TIMEOUT_INITIALIZED;
	to->to_next = NULL;
}

int timeout_add(struct timeout *to, int t)
{
	int was = timeout_del(to);
	to->to_time = osyx_bsd_ticks() + (uint64_t)(t > 0 ? t : 1);
	to->to_flags |= TIMEOUT_ONQUEUE;
	to->to_next = timeouts;
	timeouts = to;
	return !was;
}

/* Round up so a timer never fires early; widen before multiplying. */
static int timeout_units(struct timeout *to, int value, uint64_t units_per_sec)
{
	uint64_t ticks64 = value > 0 ? ((uint64_t)value * (uint64_t)hz + units_per_sec - 1) / units_per_sec : 1;
	if (ticks64 > 0x7fffffffU)
		ticks64 = 0x7fffffffU;
	return timeout_add(to, (int)ticks64);
}

int timeout_add_msec(struct timeout *to, int ms) { return timeout_units(to, ms, 1000); }
int timeout_add_usec(struct timeout *to, int us) { return timeout_units(to, us, 1000000); }
int timeout_add_sec(struct timeout *to, int s) { return timeout_units(to, s, 1); }

int timeout_del(struct timeout *to)
{
	for (struct timeout **p = &timeouts; *p; p = &(*p)->to_next) {
		if (*p == to) {
			*p = to->to_next;
			to->to_flags &= ~TIMEOUT_ONQUEUE;
			return 1;
		}
	}
	return 0;
}

int timeout_del_barrier(struct timeout *to) { return timeout_del(to); }

static struct task *tasks;
struct taskq *const systq = (struct taskq *)1;
struct taskq *const systqmp = (struct taskq *)2;

void task_set(struct task *t, void (*f)(void *), void *arg)
{
	t->t_func = f;
	t->t_arg = arg;
	t->t_flags = 0;
	t->t_next = NULL;
}

int task_add(struct taskq *q, struct task *t)
{
	(void)q;
	if (t->t_flags & TASK_ONQUEUE)
		return 0;
	t->t_flags |= TASK_ONQUEUE;
	t->t_next = tasks;
	tasks = t;
	return 1;
}

int task_del(struct taskq *q, struct task *t)
{
	(void)q;
	for (struct task **p = &tasks; *p; p = &(*p)->t_next) {
		if (*p == t) {
			*p = t->t_next;
			t->t_flags &= ~TASK_ONQUEUE;
			return 1;
		}
	}
	return 0;
}

/* ---- interrupts (polled) ---------------------------------------------------------- */

#define MAX_INTRS 16
static struct { int (*f)(void *); void *arg; } intrs[MAX_INTRS];

void *pci_intr_establish(pci_chipset_tag_t pc, pci_intr_handle_t ih, int level, int (*f)(void *), void *arg, const char *name)
{
	(void)pc; (void)ih; (void)level; (void)name;
	for (int i = 0; i < MAX_INTRS; i++) {
		if (intrs[i].f == NULL) {
			intrs[i].f = f;
			intrs[i].arg = arg;
			return &intrs[i];
		}
	}
	return NULL;
}

void pci_intr_disestablish(pci_chipset_tag_t pc, void *cookie)
{
	(void)pc;
	for (int i = 0; i < MAX_INTRS; i++)
		if (&intrs[i] == cookie)
			intrs[i].f = NULL;
}

int pci_intr_map(struct pci_attach_args *pa, pci_intr_handle_t *ih) { (void)pa; ih->ih_msi = 0; return 0; }
/* Interrupts are polled: MSI is "unavailable" so drivers keep INTx setup. */
int pci_intr_map_msi(struct pci_attach_args *pa, pci_intr_handle_t *ih) { (void)pa; (void)ih; return 1; }
int pci_intr_map_msix(struct pci_attach_args *pa, int v, pci_intr_handle_t *ih) { (void)pa; (void)v; (void)ih; return 1; }
const char *pci_intr_string(pci_chipset_tag_t pc, pci_intr_handle_t ih) { (void)pc; (void)ih; return "polled"; }

/* Runs the polled interrupt handlers and the expired timeouts. */
void osyx_bsd_run_due(void)
{
	uint64_t now = osyx_bsd_ticks();
	ticks = (int)now;
	for (int i = 0; i < MAX_INTRS; i++)
		if (intrs[i].f)
			intrs[i].f(intrs[i].arg);
	/* Unlink one at a time: a handler may add timeouts again. */
	for (;;) {
		struct timeout *due = NULL;
		for (struct timeout *t = timeouts; t; t = t->to_next)
			if (t->to_time <= now) { due = t; break; }
		if (due == NULL)
			break;
		timeout_del(due);
		due->to_func(due->to_arg);
	}
}

/*
 * Runs the queued tasks. OpenBSD runs each task queue in its own thread,
 * so a task that sleeps lets the tasks of other queues run: iwm's
 * init_task (systq) sleeps in iwm_init until its newstate_task (iwm's own
 * queue) has run. Sleepers here run queued tasks too, nested, except tasks
 * still running further up (a task never runs twice at once).
 */
#define MAX_TASK_DEPTH 4
static struct task *running_tasks[MAX_TASK_DEPTH];
static int task_depth;

static int task_running(const struct task *t)
{
	for (int i = 0; i < task_depth; i++)
		if (running_tasks[i] == t)
			return 1;
	return 0;
}

void osyx_bsd_run_tasks(void)
{
	if (task_depth == MAX_TASK_DEPTH)
		return;
	for (;;) {
		struct task **pp = &tasks, *t = tasks;
		while (t != NULL && task_running(t)) {
			pp = &t->t_next;
			t = t->t_next;
		}
		if (t == NULL)
			break;
		*pp = t->t_next;
		t->t_flags &= ~TASK_ONQUEUE;
		running_tasks[task_depth++] = t;
		t->t_func(t->t_arg);
		task_depth--;
	}
}

/* Called by the BSD service thread every tick. */
void osyx_bsd_service(void)
{
	osyx_bsd_run_due();
	osyx_bsd_run_tasks();
}

/* ---- autoconf ------------------------------------------------------------------------ */

extern const struct cfattach rgephy_ca, rlphy_ca, ukphy_ca;
extern struct cfdriver rgephy_cd, rlphy_cd, ukphy_cd;
extern const struct cfattach re_pci_ca, rl_pci_ca, iwm_ca, azalia_ca;
extern struct cfdriver re_cd, rl_cd, iwm_cd, azalia_cd;

static long any_loc[1] = { -1 };
/* PHY drivers, most specific first; ukphy (generic) matches anything. */
static struct cfdata phys[] = {
	{ &rgephy_ca, &rgephy_cd, 0, any_loc, 0 },
	{ &rlphy_ca, &rlphy_cd, 0, any_loc, 0 },
	{ &ukphy_ca, &ukphy_cd, 0, any_loc, 0 },
};
static struct cfdata pcis[] = {
	{ &re_pci_ca, &re_cd, 0, any_loc, 0 },
	{ &rl_pci_ca, &rl_cd, 0, any_loc, 0 },
	{ &iwm_ca, &iwm_cd, 0, any_loc, 0 },
	{ &azalia_ca, &azalia_cd, 0, any_loc, 0 },
};

static struct device *attach_child(struct device *parent, struct cfdata *cf, void *aux)
{
	const struct cfattach *ca = cf->cf_attach;
	struct device *dev = malloc(ca->ca_devsize, M_DEVBUF, M_NOWAIT | M_ZERO);
	if (dev == NULL)
		return NULL;
	dev->dv_class = cf->cf_driver->cd_class;
	dev->dv_parent = parent;
	dev->dv_unit = cf->cf_driver->cd_ndevs++;
	dev->dv_cfdata = cf;
	dev->dv_flags = DVF_ACTIVE;
	snprintf(dev->dv_xname, sizeof(dev->dv_xname), "%s%d", cf->cf_driver->cd_name, dev->dv_unit);
	printf("%s at %s", dev->dv_xname, parent ? parent->dv_xname : "pci");
	ca->ca_attach(parent, dev, aux);
	/* Drivers end their attach line themselves; finish it if one did not. */
	if (line_len)
		printf("\n");
	return dev;
}

struct device *config_found_sm(struct device *parent, void *aux, cfprint_t print, cfmatch_t submatch)
{
	(void)print;
	struct cfdata *best = NULL;
	int best_pri = 0;
	for (size_t i = 0; i < nitems(phys); i++) {
		int pri = submatch ? submatch(parent, &phys[i], aux) : phys[i].cf_attach->ca_match(parent, &phys[i], aux);
		if (pri > best_pri) {
			best_pri = pri;
			best = &phys[i];
		}
	}
	return best ? attach_child(parent, best, aux) : NULL;
}

int config_detach(struct device *dev, int flags)
{
	const struct cfattach *ca = dev->dv_cfdata->cf_attach;
	int e = ca->ca_detach ? ca->ca_detach(dev, flags) : 0;
	if (e == 0)
		free(dev, M_DEVBUF, ca->ca_devsize);
	return e;
}

int config_activate_children(struct device *dev, int act) { (void)dev; (void)act; return 0; }
int config_detach_children(struct device *dev, int flags) { (void)dev; (void)flags; return 0; }
const char *pci_findvendor(uint32_t id) { (void)id; return NULL; }

/* PCI id of the function being attached (read by audio_attach_mi). */
uint32_t osyx_bsd_attaching_id;

/* Offers a PCI function to the drivers; true if one attached. */
int osyx_bsd_pci_attach(uint32_t tag, unsigned bus, unsigned dev, unsigned fn)
{
	static struct osyx_dma_tag dmat;
	struct pci_attach_args pa;
	memset(&pa, 0, sizeof(pa));
	pa.pa_iot = X86_BUS_SPACE_IO;
	pa.pa_memt = X86_BUS_SPACE_MEM;
	pa.pa_dmat = &dmat;
	pa.pa_dmat64 = &dmat;
	pa.pa_bus = bus;
	pa.pa_device = dev;
	pa.pa_function = fn;
	pa.pa_tag = tag;
	pa.pa_id = osyx_bsd_pci_read(tag, PCI_ID_REG);
	pa.pa_class = osyx_bsd_pci_read(tag, PCI_CLASS_REG);
	pa.pa_flags = PCI_FLAGS_IO_ENABLED | PCI_FLAGS_MEM_ENABLED;
	pa.pa_intrpin = 1;
	struct cfdata *best = NULL;
	int best_pri = 0;
	for (size_t i = 0; i < nitems(pcis); i++) {
		int pri = pcis[i].cf_attach->ca_match(NULL, &pcis[i], &pa);
		if (pri > best_pri) {
			best_pri = pri;
			best = &pcis[i];
		}
	}
	if (best == NULL)
		return 0;
	/*
	 * Power the function up first, as OpenBSD's pci_probe_device does:
	 * firmware may leave it in D3 (laptop Wi-Fi cards), where it does
	 * not decode its BARs. Leaving D3hot can reset the function, so the
	 * BARs are saved and written back.
	 */
	int pm;
	if (pci_get_capability(NULL, tag, PCI_CAP_PWRMGMT, &pm, NULL)) {
		pcireg_t pmcsr = osyx_bsd_pci_read(tag, pm + PCI_PMCSR);
		if (pmcsr & PCI_PMCSR_STATE_MASK) {
			pcireg_t bars[6];
			for (int i = 0; i < 6; i++)
				bars[i] = osyx_bsd_pci_read(tag, PCI_MAPREG_START + 4 * i);
			printf("bsd: %02x:%02x.%d was in power state D%d, waking it\n", bus, dev, fn, (int)(pmcsr & PCI_PMCSR_STATE_MASK));
			pci_set_powerstate(NULL, tag, PCI_PMCSR_STATE_D0);
			for (int i = 0; i < 6; i++)
				if (osyx_bsd_pci_read(tag, PCI_MAPREG_START + 4 * i) != bars[i])
					osyx_bsd_pci_write(tag, PCI_MAPREG_START + 4 * i, bars[i]);
		}
	}
	/* Memory/I/O decoding and bus mastering on, INTx left as it is. */
	pcireg_t cmd = osyx_bsd_pci_read(tag, PCI_COMMAND_STATUS_REG);
	osyx_bsd_pci_write(tag, PCI_COMMAND_STATUS_REG, cmd | PCI_COMMAND_IO_ENABLE | PCI_COMMAND_MEM_ENABLE | PCI_COMMAND_MASTER_ENABLE);
	osyx_bsd_attaching_id = pa.pa_id;
	return attach_child(NULL, best, &pa) != NULL;
}

/* ---- PCI ---------------------------------------------------------------------------- */

pcireg_t pci_conf_read(pci_chipset_tag_t pc, pcitag_t tag, int reg) { (void)pc; return osyx_bsd_pci_read(tag, reg); }
void pci_conf_write(pci_chipset_tag_t pc, pcitag_t tag, int reg, pcireg_t v) { (void)pc; osyx_bsd_pci_write(tag, reg, v); }

int pci_matchbyid(struct pci_attach_args *pa, const struct pci_matchid *ids, int n)
{
	for (int i = 0; i < n; i++)
		if (PCI_VENDOR(pa->pa_id) == ids[i].pm_vid && PCI_PRODUCT(pa->pa_id) == ids[i].pm_pid)
			return 1;
	return 0;
}

pcireg_t pci_mapreg_type(pci_chipset_tag_t pc, pcitag_t tag, int reg)
{
	(void)pc;
	pcireg_t v = osyx_bsd_pci_read(tag, reg);
	if (v & PCI_MAPREG_TYPE_IO)
		return PCI_MAPREG_TYPE_IO;
	return v & (PCI_MAPREG_TYPE_MASK | PCI_MAPREG_MEM_TYPE_MASK);
}

int pci_mapreg_map(struct pci_attach_args *pa, int reg, pcireg_t type, int flags, bus_space_tag_t *tagp,
    bus_space_handle_t *handlep, bus_addr_t *basep, bus_size_t *sizep, bus_size_t maxsize)
{
	(void)flags;
	pcitag_t tag = pa->pa_tag;
	pcireg_t low = osyx_bsd_pci_read(tag, reg);
	pcireg_t cmd = osyx_bsd_pci_read(tag, PCI_COMMAND_STATUS_REG);
	osyx_bsd_pci_write(tag, PCI_COMMAND_STATUS_REG, cmd & ~(PCI_COMMAND_IO_ENABLE | PCI_COMMAND_MEM_ENABLE));
	osyx_bsd_pci_write(tag, reg, 0xffffffff);
	pcireg_t mask = osyx_bsd_pci_read(tag, reg);
	osyx_bsd_pci_write(tag, reg, low);
	uint64_t base, size;
	int io = (low & PCI_MAPREG_TYPE_IO) != 0;
	if (io) {
		base = low & ~3u;
		size = (uint32_t)(~(mask & ~3u) + 1) & 0xffff;
	} else {
		uint64_t hi = 0, hmask = 0xffffffff;
		if (PCI_MAPREG_MEM_TYPE(low) == PCI_MAPREG_MEM_TYPE_64BIT) {
			hi = osyx_bsd_pci_read(tag, reg + 4);
			osyx_bsd_pci_write(tag, reg + 4, 0xffffffff);
			hmask = osyx_bsd_pci_read(tag, reg + 4);
			osyx_bsd_pci_write(tag, reg + 4, (pcireg_t)hi);
		}
		base = (hi << 32) | (low & ~0xfu);
		size = ~((hmask << 32) | (mask & ~0xfu)) + 1;
	}
	osyx_bsd_pci_write(tag, PCI_COMMAND_STATUS_REG, cmd);
	if ((type == PCI_MAPREG_TYPE_IO) != io || base == 0 || (mask & ~0xfu) == 0) {
		printf("bsd: BAR 0x%x of 0x%x: value 0x%x, size mask 0x%x, base 0x%llx, wanted %s, command 0x%x: cannot map\n",
		    reg, tag, low, mask, (unsigned long long)base, type == PCI_MAPREG_TYPE_IO ? "I/O" : "memory", cmd);
		return EINVAL;
	}
	if (maxsize && size > maxsize)
		size = maxsize;
	bus_space_handle_t h;
	if (io) {
		h = base;
	} else {
		h = osyx_bsd_map_mmio(base, size);
		if (h == 0) {
			printf("bsd: BAR 0x%x of 0x%x: cannot map 0x%llx (+0x%llx)\n", reg, tag, (unsigned long long)base, (unsigned long long)size);
			return ENOMEM;
		}
		/* High Definition Audio controller registers (see audio.c). */
		if (PCI_CLASS(pa->pa_class) == PCI_CLASS_MULTIMEDIA && PCI_SUBCLASS(pa->pa_class) == PCI_SUBCLASS_MULTIMEDIA_HDAUDIO)
			osyx_bsd_hda_regs(h);
	}
	if (tagp) *tagp = io ? X86_BUS_SPACE_IO : X86_BUS_SPACE_MEM;
	if (handlep) *handlep = h;
	if (basep) *basep = base;
	if (sizep) *sizep = size;
	return 0;
}

int pci_get_capability(pci_chipset_tag_t pc, pcitag_t tag, int capid, int *offset, pcireg_t *value)
{
	(void)pc;
	if (!(osyx_bsd_pci_read(tag, PCI_COMMAND_STATUS_REG) & PCI_STATUS_CAPLIST_SUPPORT))
		return 0;
	int off = osyx_bsd_pci_read(tag, PCI_CAPLISTPTR_REG) & 0xfc;
	for (int guard = 0; off && guard < 48; guard++) {
		pcireg_t r = osyx_bsd_pci_read(tag, off);
		if ((int)(r & 0xff) == capid) {
			if (offset) *offset = off;
			if (value) *value = r;
			return 1;
		}
		off = (r >> 8) & 0xfc;
	}
	return 0;
}

int pci_set_powerstate(pci_chipset_tag_t pc, pcitag_t tag, int state)
{
	int off;
	if (!pci_get_capability(pc, tag, PCI_CAP_PWRMGMT, &off, NULL))
		return EOPNOTSUPP;
	pcireg_t r = osyx_bsd_pci_read(tag, off + PCI_PMCSR);
	osyx_bsd_pci_write(tag, off + PCI_PMCSR, (r & ~PCI_PMCSR_STATE_MASK) | (pcireg_t)state);
	if ((r & PCI_PMCSR_STATE_MASK) != (pcireg_t)state)
		delay(10000);
	return 0;
}

/* ---- bus_dma -------------------------------------------------------------------------- */

int bus_dmamap_create(bus_dma_tag_t t, bus_size_t size, int nsegs, bus_size_t maxsegsz, bus_size_t boundary, int flags, bus_dmamap_t *mapp)
{
	(void)t; (void)boundary;
	size_t bytes = sizeof(struct bus_dmamap) + (size_t)(nsegs - 1) * sizeof(bus_dma_segment_t);
	bus_dmamap_t m = malloc(bytes, M_DEVBUF, (flags & BUS_DMA_NOWAIT ? M_NOWAIT : M_WAITOK) | M_ZERO);
	if (m == NULL)
		return ENOMEM;
	m->dm_size = size;
	m->dm_maxsegs = nsegs;
	m->dm_maxsegsz = maxsegsz;
	*mapp = m;
	return 0;
}

void bus_dmamap_destroy(bus_dma_tag_t t, bus_dmamap_t m)
{
	(void)t;
	free(m, M_DEVBUF, 0);
}

/* Appends [va, va+len) to the map, one segment per physically contiguous run. */
static int map_range(bus_dmamap_t m, uint64_t va, uint64_t len)
{
	while (len > 0) {
		uint64_t pa = osyx_bsd_virt_to_phys(va);
		uint64_t chunk = PAGE_SIZE - (va & (PAGE_SIZE - 1));
		if (chunk > len)
			chunk = len;
		if (pa == 0 || pa + chunk > 0x100000000ULL)
			return EFBIG;
		bus_dma_segment_t *last = m->dm_nsegs ? &m->dm_segs[m->dm_nsegs - 1] : NULL;
		if (last && last->ds_addr + last->ds_len == pa && last->ds_len + chunk <= m->dm_maxsegsz) {
			last->ds_len += chunk;
		} else {
			if (m->dm_nsegs == m->dm_maxsegs)
				return EFBIG;
			m->dm_segs[m->dm_nsegs].ds_addr = pa;
			m->dm_segs[m->dm_nsegs].ds_len = chunk;
			m->dm_nsegs++;
		}
		va += chunk;
		len -= chunk;
	}
	return 0;
}

int bus_dmamap_load(bus_dma_tag_t t, bus_dmamap_t m, void *buf, bus_size_t len, struct proc *p, int flags)
{
	(void)t; (void)p; (void)flags;
	m->dm_nsegs = 0;
	m->dm_mapsize = 0;
	if (len > m->dm_size)
		return EINVAL;
	int e = map_range(m, (uint64_t)buf, len);
	if (e) {
		m->dm_nsegs = 0;
		return e;
	}
	m->dm_mapsize = len;
	return 0;
}

int bus_dmamap_load_mbuf(bus_dma_tag_t t, bus_dmamap_t m, struct mbuf *chain, int flags)
{
	(void)t; (void)flags;
	m->dm_nsegs = 0;
	m->dm_mapsize = 0;
	for (struct mbuf *x = chain; x; x = x->m_next) {
		if (x->m_len == 0)
			continue;
		int e = map_range(m, (uint64_t)x->m_data, x->m_len);
		if (e) {
			m->dm_nsegs = 0;
			return e;
		}
		m->dm_mapsize += x->m_len;
	}
	return 0;
}

void bus_dmamap_unload(bus_dma_tag_t t, bus_dmamap_t m)
{
	(void)t;
	m->dm_nsegs = 0;
	m->dm_mapsize = 0;
}

int bus_dmamem_alloc(bus_dma_tag_t t, bus_size_t size, bus_size_t align, bus_size_t boundary, bus_dma_segment_t *segs, int nsegs, int *rsegs, int flags)
{
	(void)t; (void)boundary; (void)nsegs; (void)flags;
	uint64_t pa = osyx_bsd_dma_alloc(size, align > PAGE_SIZE ? align : PAGE_SIZE);
	if (pa == 0)
		return ENOMEM;
	segs[0].ds_addr = pa;
	segs[0].ds_len = size;
	*rsegs = 1;
	return 0;
}

void bus_dmamem_free(bus_dma_tag_t t, bus_dma_segment_t *segs, int nsegs)
{
	(void)t;
	for (int i = 0; i < nsegs; i++)
		osyx_bsd_dma_free(segs[i].ds_addr, segs[i].ds_len);
}

int bus_dmamem_map(bus_dma_tag_t t, bus_dma_segment_t *segs, int nsegs, size_t size, caddr_t *kvap, int flags)
{
	(void)t; (void)nsegs; (void)size; (void)flags;
	*kvap = (caddr_t)osyx_bsd_phys_to_virt(segs[0].ds_addr);
	return 0;
}

void bus_dmamem_unmap(bus_dma_tag_t t, caddr_t kva, size_t size) { (void)t; (void)kva; (void)size; }

/* ---- mbufs ---------------------------------------------------------------------------- */

static struct mbuf *m_alloc(size_t bufsize, int flags)
{
	struct mbuf *m = malloc(sizeof(*m), M_DEVBUF, M_NOWAIT | M_ZERO);
	if (m == NULL)
		return NULL;
	size_t size = roundup(bufsize ? bufsize : MHLEN, PAGE_SIZE);
	uint64_t pa = osyx_bsd_dma_alloc(size, PAGE_SIZE);
	if (pa == 0) {
		free(m, M_DEVBUF, sizeof(*m));
		return NULL;
	}
	m->m_bufphys = pa;
	m->m_bufsize = size;
	m->m_ext.ext_buf = (caddr_t)osyx_bsd_phys_to_virt(pa);
	m->m_ext.ext_size = (unsigned int)(bufsize ? bufsize : MHLEN);
	m->m_data = m->m_ext.ext_buf;
	m->m_flags = (unsigned short)flags;
	m->m_type = MT_DATA;
	return m;
}

struct mbuf *osyx_bsd_m_alloc(size_t bufsize, int flags) { return m_alloc(bufsize, flags); }

struct mbuf *m_gethdr(int how, int type) { (void)how; (void)type; return m_alloc(MHLEN, M_PKTHDR); }
struct mbuf *m_get(int how, int type) { (void)how; (void)type; return m_alloc(MLEN, 0); }

struct mbuf *m_clget(struct mbuf *m, int how, unsigned int size)
{
	(void)how;
	if (m == NULL)
		return m_alloc(size, M_PKTHDR | M_EXT);
	/* Swap in a buffer of `size` bytes. */
	struct mbuf *n = m_alloc(size, 0);
	if (n == NULL)
		return NULL;
	osyx_bsd_dma_free(m->m_bufphys, m->m_bufsize);
	m->m_bufphys = n->m_bufphys;
	m->m_bufsize = n->m_bufsize;
	m->m_ext = n->m_ext;
	m->m_data = m->m_ext.ext_buf;
	m->m_flags |= M_EXT;
	free(n, M_DEVBUF, sizeof(*n));
	return m;
}

struct mbuf *m_free(struct mbuf *m)
{
	struct mbuf *next = m->m_next;
	osyx_bsd_dma_free(m->m_bufphys, m->m_bufsize);
	free(m, M_DEVBUF, sizeof(*m));
	return next;
}

void m_freem(struct mbuf *m)
{
	while (m)
		m = m_free(m);
}

void m_adj(struct mbuf *mp, int req)
{
	if (mp == NULL)
		return;
	if (req >= 0) {
		int len = req;
		for (struct mbuf *m = mp; m && len > 0; m = m->m_next) {
			int n = (int)m->m_len < len ? (int)m->m_len : len;
			m->m_len -= n;
			m->m_data += n;
			len -= n;
		}
		if (mp->m_flags & M_PKTHDR)
			mp->m_pkthdr.len -= req - len;
	} else {
		int total = 0;
		for (struct mbuf *m = mp; m; m = m->m_next)
			total += m->m_len;
		int keep = total + req < 0 ? 0 : total + req;
		for (struct mbuf *m = mp; m; m = m->m_next) {
			if ((int)m->m_len >= keep) {
				m->m_len = keep;
				keep = 0;
			} else {
				keep -= m->m_len;
			}
		}
		if (mp->m_flags & M_PKTHDR)
			mp->m_pkthdr.len = total + req < 0 ? 0 : total + req;
	}
}

void m_copydata(struct mbuf *m, int off, int len, void *out)
{
	uint8_t *p = out;
	for (; m && off >= (int)m->m_len; m = m->m_next)
		off -= m->m_len;
	for (; m && len > 0; m = m->m_next, off = 0) {
		int n = (int)m->m_len - off < len ? (int)m->m_len - off : len;
		memcpy(p, m->m_data + off, n);
		p += n;
		len -= n;
	}
}

int m_copyback(struct mbuf *m, int off, int len, const void *in, int how)
{
	(void)how;
	const uint8_t *p = in;
	for (; m && off >= (int)m->m_len; m = m->m_next)
		off -= m->m_len;
	for (; m && len > 0; m = m->m_next, off = 0) {
		int n = (int)m->m_len - off < len ? (int)m->m_len - off : len;
		memcpy(m->m_data + off, p, n);
		p += n;
		len -= n;
	}
	return len > 0 ? ENOBUFS : 0;
}

struct mbuf *m_devget(char *buf, int len, int off)
{
	struct mbuf *m = m_alloc((size_t)(len + off), M_PKTHDR);
	if (m == NULL)
		return NULL;
	m->m_data += off;
	memcpy(m->m_data, buf, len);
	m->m_len = len;
	m->m_pkthdr.len = len;
	return m;
}

struct mbuf *m_getptr(struct mbuf *m, int loc, int *off)
{
	for (; m; m = m->m_next) {
		if (loc < (int)m->m_len) {
			*off = loc;
			return m;
		}
		loc -= m->m_len;
	}
	return NULL;
}

/* Copies a chain into its first mbuf's (enlarged) buffer: one DMA segment. */
int m_defrag(struct mbuf *m, int how)
{
	(void)how;
	if (m->m_next == NULL)
		return 0;
	int total = m->m_pkthdr.len;
	struct mbuf *n = m_alloc((size_t)total, 0);
	if (n == NULL)
		return ENOBUFS;
	m_copydata(m, 0, total, n->m_data);
	m_freem(m->m_next);
	m->m_next = NULL;
	osyx_bsd_dma_free(m->m_bufphys, m->m_bufsize);
	m->m_bufphys = n->m_bufphys;
	m->m_bufsize = n->m_bufsize;
	m->m_ext = n->m_ext;
	m->m_data = n->m_data;
	m->m_len = total;
	m->m_flags |= M_EXT;
	free(n, M_DEVBUF, sizeof(*n));
	return 0;
}

struct mbuf *m_pullup(struct mbuf *m, int len)
{
	if ((int)m->m_len >= len)
		return m;
	if (m_defrag(m, M_NOWAIT) != 0 || (int)m->m_len < len) {
		m_freem(m);
		return NULL;
	}
	return m;
}

struct mbuf *m_prepend(struct mbuf *m, int len, int how)
{
	(void)how;
	if (M_LEADINGSPACE(m) >= (size_t)len) {
		m->m_data -= len;
		m->m_len += len;
		if (m->m_flags & M_PKTHDR)
			m->m_pkthdr.len += len;
		return m;
	}
	/* No room in front: a new mbuf ahead of the chain takes over the
	 * packet header, as in OpenBSD. */
	struct mbuf *n = len <= MHLEN ? m_alloc(MHLEN, 0) : NULL;
	if (n == NULL) {
		m_freem(m);
		return NULL;
	}
	n->m_flags = (n->m_flags & M_EXT) | (m->m_flags & ~M_EXT);
	if (m->m_flags & M_PKTHDR) {
		n->m_pkthdr = m->m_pkthdr;
		n->m_pkthdr.len += len;
		m->m_flags &= ~M_PKTHDR;
	}
	n->m_next = m;
	n->m_data += MHLEN - len;
	n->m_len = (unsigned int)len;
	return n;
}

void ml_init(struct mbuf_list *ml) { ml->ml_head = ml->ml_tail = NULL; ml->ml_len = 0; }

void ml_enqueue(struct mbuf_list *ml, struct mbuf *m)
{
	m->m_nextpkt = NULL;
	if (ml->ml_tail)
		ml->ml_tail->m_nextpkt = m;
	else
		ml->ml_head = m;
	ml->ml_tail = m;
	ml->ml_len++;
}

struct mbuf *ml_dequeue(struct mbuf_list *ml)
{
	struct mbuf *m = ml->ml_head;
	if (m) {
		ml->ml_head = m->m_nextpkt;
		if (ml->ml_head == NULL)
			ml->ml_tail = NULL;
		m->m_nextpkt = NULL;
		ml->ml_len--;
	}
	return m;
}

unsigned int ml_purge(struct mbuf_list *ml)
{
	unsigned int n = 0;
	struct mbuf *m;
	while ((m = ml_dequeue(ml)) != NULL) {
		m_freem(m);
		n++;
	}
	return n;
}

/* ---- interface queues and the network stack ----------------------------------------------- */

int ifq_enqueue(struct ifqueue *q, struct mbuf *m)
{
	if (q->ifq_maxlen && q->ifq_list.ml_len >= q->ifq_maxlen) {
		q->ifq_qdrops++;
		m_freem(m);
		return ENOBUFS;
	}
	ml_enqueue(&q->ifq_list, m);
	return 0;
}

struct mbuf *ifq_dequeue(struct ifqueue *q) { return ml_dequeue(&q->ifq_list); }
struct mbuf *ifq_deq_begin(struct ifqueue *q) { return q->ifq_list.ml_head; }
void ifq_deq_commit(struct ifqueue *q, struct mbuf *m) { (void)m; (void)ml_dequeue(&q->ifq_list); }
void ifq_deq_rollback(struct ifqueue *q, struct mbuf *m) { (void)q; (void)m; }
unsigned int ifq_purge(struct ifqueue *q) { return ml_purge(&q->ifq_list); }

static void start(struct ifnet *ifp)
{
	if (ifp->if_qstart)
		ifp->if_qstart(&ifp->if_snd);
	else if (ifp->if_start)
		ifp->if_start(ifp);
}

void osyx_bsd_start(struct ifnet *ifp) { start(ifp); }

void ifq_restart(struct ifqueue *q) { ifq_clr_oactive(q); start(q->ifq_if); }
void ifq_serialize(struct ifqueue *q, struct task *t) { (void)q; t->t_func(t->t_arg); }

void if_attach(struct ifnet *ifp)
{
	ifp->if_snd.ifq_if = ifp;
	ifp->if_rcv.ifiq_if = ifp;
	ifp->if_ifqs[0] = &ifp->if_snd;
	if (ifp->if_snd.ifq_maxlen == 0)
		ifp->if_snd.ifq_maxlen = 256;
	ifp->if_osyx_handle = -1;
}

void ether_ifattach(struct ifnet *ifp)
{
	struct arpcom *ac = (struct arpcom *)ifp;
	ifp->if_type = IFT_ETHER;
	if (ifp->if_mtu == 0)
		ifp->if_mtu = ETHERMTU;
	ifp->if_osyx_handle = osyx_bsd_ether_attach(ifp, ac->ac_enaddr, ifp->if_xname);
}

/* The wireless address is discovered by the deferred firmware preinit. */
void osyx_bsd_mac_address(struct ifnet *ifp, uint8_t *mac)
{
	memcpy(mac, ((struct arpcom *)ifp)->ac_enaddr, ETHER_ADDR_LEN);
}

void if_detach(struct ifnet *ifp) { ifq_purge(&ifp->if_snd); }
void ether_ifdetach(struct ifnet *ifp) { (void)ifp; }
void if_counters_alloc(struct ifnet *ifp) { (void)ifp; }

/* Received frames go to the OSyx stack as one contiguous copy each. */
void if_input(struct ifnet *ifp, struct mbuf_list *ml)
{
	static uint8_t frame[MAXMCLBYTES];
	struct mbuf *m;
	while ((m = ml_dequeue(ml)) != NULL) {
		int len = m->m_flags & M_PKTHDR ? m->m_pkthdr.len : (int)m->m_len;
		if (len > 0 && len <= (int)sizeof(frame) && ifp->if_osyx_handle >= 0) {
			m_copydata(m, 0, len, frame);
			osyx_bsd_ether_input(ifp->if_osyx_handle, frame, (size_t)len);
			ifp->if_ipackets++;
		}
		m_freem(m);
	}
}

int ifiq_input(struct ifiqueue *iq, struct mbuf_list *ml)
{
	if_input(iq->ifiq_if, ml);
	return 0;
}

void if_link_state_change(struct ifnet *ifp)
{
	if (ifp->if_osyx_handle >= 0)
		osyx_bsd_link_state(ifp->if_osyx_handle, LINK_STATE_IS_UP(ifp->if_link_state) && ifp->if_link_state != LINK_STATE_UNKNOWN);
}

int ether_ioctl(struct ifnet *ifp, struct arpcom *ac, unsigned long cmd, caddr_t data)
{
	(void)ifp; (void)ac; (void)data;
	switch (cmd) {
	case SIOCADDMULTI:
	case SIOCDELMULTI:
		return ENETRESET;
	default:
		return ENOTTY;
	}
}

const uint8_t etherbroadcastaddr[ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

char *ether_sprintf(uint8_t *a)
{
	static char buf[18];
	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5]);
	return buf;
}

uint32_t ether_crc32_le(const uint8_t *buf, size_t len)
{
	uint32_t crc = 0xffffffff;
	for (size_t i = 0; i < len; i++) {
		crc ^= buf[i];
		for (int b = 0; b < 8; b++)
			crc = (crc >> 1) ^ (crc & 1 ? 0xedb88320 : 0);
	}
	return crc;
}

uint32_t ether_crc32_be(const uint8_t *buf, size_t len)
{
	uint32_t crc = 0xffffffff;
	for (size_t i = 0; i < len; i++) {
		uint8_t c = buf[i];
		for (int b = 0; b < 8; b++, c >>= 1) {
			uint32_t carry = ((crc & 0x80000000) ? 1 : 0) ^ (c & 1);
			crc <<= 1;
			if (carry)
				crc = (crc ^ 0x04c11db6) | carry;
		}
	}
	return crc;
}

int in_cksum(struct mbuf *m, int len)
{
	uint32_t sum = 0;
	int odd = 0;
	for (; m && len > 0; m = m->m_next) {
		int n = (int)m->m_len < len ? (int)m->m_len : len;
		const uint8_t *p = (const uint8_t *)m->m_data;
		for (int i = 0; i < n; i++, odd ^= 1)
			sum += odd ? p[i] : (uint32_t)p[i] << 8;
		len -= n;
	}
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (int)(~sum & 0xffff);
}

/* The OSyx stack computes every checksum itself and never asks a driver
 * to: nothing is left to finish here. */
void in_delayed_cksum(struct mbuf *m)
{
	m->m_pkthdr.csum_flags &= ~(M_TCP_CSUM_OUT | M_UDP_CSUM_OUT | M_ICMP_CSUM_OUT);
}

void if_rxr_init(struct if_rxring *r, unsigned int lwm, unsigned int hwm)
{
	memset(r, 0, sizeof(*r));
	r->rxr_lwm = lwm ? lwm : 1;
	r->rxr_hwm = hwm;
	r->rxr_cwm = hwm;
}

unsigned int if_rxr_get(struct if_rxring *r, unsigned int max)
{
	unsigned int room = r->rxr_cwm > r->rxr_alive ? r->rxr_cwm - r->rxr_alive : 0;
	unsigned int n = room < max ? room : max;
	r->rxr_alive += n;
	return n;
}

int if_rxr_ioctl(struct if_rxrinfo *i, const char *n, unsigned int s, struct if_rxring *r)
{
	(void)i; (void)n; (void)s; (void)r;
	return ENOTTY;
}

/* ---- entry points for the Rust side -------------------------------------------------------- */

/* Brings an interface up (SIOCSIFFLAGS with IFF_UP), as ifconfig would. */
int osyx_bsd_ifup(struct ifnet *ifp)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	ifp->if_flags |= IFF_UP | IFF_BROADCAST | IFF_MULTICAST;
	return ifp->if_ioctl(ifp, SIOCSIFFLAGS, (caddr_t)&ifr);
}

/* Queues one frame for transmission and kicks the driver. */
int osyx_bsd_output(struct ifnet *ifp, const uint8_t *frame, size_t len)
{
	if (!(ifp->if_flags & IFF_RUNNING))
		return ENETDOWN;
	/* Room in front for headers the driver prepends: net80211 turns the
	 * Ethernet header into an 802.11 header and LLC/SNAP. */
	const size_t headroom = 128;
	struct mbuf *m = m_alloc(headroom + len, M_PKTHDR);
	if (m == NULL)
		return ENOBUFS;
	m->m_data += headroom;
	memcpy(m->m_data, frame, len);
	m->m_len = (unsigned int)len;
	m->m_pkthdr.len = (int)len;
	int e = ifq_enqueue(&ifp->if_snd, m);
	if (e == 0) {
		ifp->if_opackets++;
		if (!ifq_is_oactive(&ifp->if_snd))
			start(ifp);
	}
	return e;
}

int osyx_bsd_link_is_up(struct ifnet *ifp)
{
	return (ifp->if_flags & IFF_RUNNING) && ifp->if_link_state >= LINK_STATE_UP;
}

/*
 * What the PHY reports (SIOCGIFMEDIA, as ifconfig(8) shows it): the IFM_*
 * status bits (IFM_AVALID, IFM_ACTIVE) and in `*active` the media in use.
 * Returns 0 when the driver has no media to report.
 */
uint64_t osyx_bsd_media(struct ifnet *ifp, uint64_t *active)
{
	struct ifmediareq ifmr;
	memset(&ifmr, 0, sizeof(ifmr));
	strlcpy(ifmr.ifm_name, ifp->if_xname, sizeof(ifmr.ifm_name));
	if (ifp->if_ioctl(ifp, SIOCGIFMEDIA, (caddr_t)&ifmr) != 0)
		return 0;
	*active = ifmr.ifm_active;
	return ifmr.ifm_status;
}

void osyx_bsd_counters(struct ifnet *ifp, uint64_t out[4])
{
	out[0] = ifp->if_ipackets;
	out[1] = ifp->if_opackets;
	out[2] = ifp->if_ierrors;
	out[3] = ifp->if_oerrors;
}
