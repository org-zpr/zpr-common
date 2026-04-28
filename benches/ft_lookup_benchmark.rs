/// Benchmarks for FiveTupleLookupTable
use criterion::{criterion_group, criterion_main};

#[cfg(all(
    feature = "vsapi",
    any(
        feature = "rcu-aarc",
        feature = "rcu-arc-swap",
        feature = "rcu-crossbeam-epoch",
        feature = "rcu-mutex-arc",
        feature = "rcu-rwlock"
    )
))]
mod bench_impl {
    use criterion::{BatchSize, BenchmarkId, Criterion};
    use rand::RngExt;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::time::SystemTime;
    use zpr::five_tuple_lookup_table::FiveTupleLookupTable;
    use zpr::packet_info::{L3Type, VisaId};
    use zpr::vsapi_types::{
        DockPep, EndpointT, KeySet, TcpUdpPep, Visa, VsapiFiveTuple, vsapi_ip_number,
    };

    fn make_visa(
        source: [u8; 16],
        dest: [u8; 16],
        proto: u8,
        source_port: u16,
        dest_port: u16,
    ) -> Result<Visa, &'static str> {
        let pep = TcpUdpPep::new(source_port, dest_port, EndpointT::Any);
        let dock_pep = match proto {
            vsapi_ip_number::TCP => DockPep::TCP(pep),
            vsapi_ip_number::UDP => DockPep::UDP(pep),
            _ => return Err("unsupported protocol"),
        };
        Ok(Visa::new(
            0,
            0,
            SystemTime::UNIX_EPOCH,
            IpAddr::from(source),
            IpAddr::from(dest),
            dock_pep,
            KeySet::default(),
            None,
        ))
    }

    fn addr_bytes_from_usize(i: usize) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[0] = 0x20; // global unicast prefix
        addr[8..16].copy_from_slice(&(i as u64).to_be_bytes());
        addr
    }

    /// Build a table with n visas, each with a unique dest_addr
    /// All the visas have the same values for the other elements of the FT
    ///
    /// Returns the FiveTupleLookupTable, and a Vector of VsapiFiveTuples that can be used to
    /// lookup Visas within the table
    fn table_unique_dest_addrs(n: usize) -> (FiveTupleLookupTable, Vec<VsapiFiveTuple>) {
        let source = addr_bytes_from_usize(0xFFFF_FFFF);
        let mut hash: HashMap<VisaId, Visa> = HashMap::with_capacity(n);
        let mut fts = Vec::with_capacity(n);
        for i in 0..n {
            let dest = addr_bytes_from_usize(i);
            hash.insert(
                i as VisaId + 1,
                make_visa(source, dest, vsapi_ip_number::TCP, 1000, 80).unwrap(),
            );
            fts.push(VsapiFiveTuple::new(
                L3Type::Ipv6,
                IpAddr::from(source),
                IpAddr::from(dest),
                vsapi_ip_number::TCP,
                1000,
                80,
            ));
        }
        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);
        (table, fts)
    }

    /// Build a table with n visas sharing the same dest/source addresses but distinct dest ports
    /// Ports are arranged in groups of group_size with a 1-port gap between groups
    ///
    /// Returns the FiveTupleLookupTable, and a Vector of VsapiFiveTuples that can be used to
    /// lookup Visas within the table    
    fn table_multival_dest_ports(
        n: usize,
        group_size: usize,
    ) -> (FiveTupleLookupTable, Vec<VsapiFiveTuple>) {
        assert!(group_size > 0, "group_size must be > 0");
        assert!(
            n / group_size * (group_size + 1) <= 65535, // group_size + 1 to account for gap between groups
            "port space exhausted"
        );
        let source = addr_bytes_from_usize(0xFFFF_FFFF);
        let dest = addr_bytes_from_usize(1);
        let mut hash: HashMap<VisaId, Visa> = HashMap::with_capacity(n);
        let mut fts = Vec::with_capacity(n);
        for i in 0..n {
            let group = i / group_size;
            let pos_in_group = i % group_size;
            let dest_port = (group * (group_size + 1) + pos_in_group + 1) as u16;
            hash.insert(
                i as VisaId + 1,
                make_visa(source, dest, vsapi_ip_number::TCP, 1000, dest_port).unwrap(),
            );
            fts.push(VsapiFiveTuple::new(
                L3Type::Ipv6,
                IpAddr::from(source),
                IpAddr::from(dest),
                vsapi_ip_number::TCP,
                1000,
                dest_port,
            ));
        }
        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);
        (table, fts)
    }

    /// Build a table with n visas, each with a unique dest address and both ports wildcarded
    ///
    /// Returns the FiveTupleLookupTable, and a Vector of VsapiFiveTuples that can be used to
    /// lookup Visas within the table    
    fn table_wildcard_ports(n: usize) -> (FiveTupleLookupTable, Vec<VsapiFiveTuple>) {
        let source = addr_bytes_from_usize(0xFFFF_FFFF);
        let mut hash: HashMap<VisaId, Visa> = HashMap::with_capacity(n);
        let mut fts = Vec::with_capacity(n);
        for i in 0..n {
            let dest = addr_bytes_from_usize(i);
            hash.insert(
                i as VisaId + 1,
                make_visa(source, dest, vsapi_ip_number::TCP, 0, 0).unwrap(),
            );
            fts.push(VsapiFiveTuple::new(
                L3Type::Ipv6,
                IpAddr::from(source),
                IpAddr::from(dest),
                vsapi_ip_number::TCP,
                1234, // arbitrary
                5678, // arbitrary
            ));
        }
        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);
        (table, fts)
    }

    /// Build a table with one visa with a wildcarded dest port and n visas with a specified dest port,
    /// all with the same dest/source address. Combining a Wildcard with specific tests the Wildcard -> Multival path
    /// Specified dest ports are arranged in groups of group_size with a 1-port gap between groups
    ///
    /// Returns the FiveTupleLookupTable, and a Vector of VsapiFiveTuples that can be used to
    /// lookup Visas within the table
    fn table_mixed_wildcard(
        n: usize,
        group_size: usize,
    ) -> (FiveTupleLookupTable, Vec<VsapiFiveTuple>) {
        assert!(group_size > 0, "group_size must be > 0");
        let n_groups = n / group_size;
        assert!(n_groups * (group_size + 1) <= 65535, "port space exhausted");
        let source = addr_bytes_from_usize(0xFFFF_FFFF);
        let dest = addr_bytes_from_usize(1);
        let mut hash: HashMap<VisaId, Visa> = HashMap::with_capacity(n + 1);
        let mut fts = Vec::with_capacity(n);
        hash.insert(
            1,
            make_visa(source, dest, vsapi_ip_number::TCP, 1000, 0).unwrap(),
        ); // wildcard dest port
        for i in 0..n {
            let group = i / group_size;
            let pos_in_group = i % group_size;
            let port = (group * (group_size + 1) + pos_in_group + 1) as u16;
            hash.insert(
                i as VisaId + 2,
                make_visa(source, dest, vsapi_ip_number::TCP, 1000, port).unwrap(),
            );
            fts.push(VsapiFiveTuple::new(
                L3Type::Ipv6,
                IpAddr::from(source),
                IpAddr::from(dest),
                vsapi_ip_number::TCP,
                1000,
                port,
            ));
        }
        let table = FiveTupleLookupTable::new();
        table.build_table_from_hash(&hash);
        (table, fts)
    }

    /// Table with unique dest addrs, tests with varying number of visas inside the table, from 1 to 1000
    pub fn bench_find_match_unique_dest(c: &mut Criterion) {
        let mut group = c.benchmark_group("find_match/unique_dest");
        for &n in &[1, 10, 100, 1000] {
            let (table, fts) = table_unique_dest_addrs(n);
            let ft = fts[rand::rng().random_range(0..fts.len())];
            group.bench_with_input(BenchmarkId::from_parameter(n), &ft, |b, &ft| {
                b.iter(|| table.find_match(ft));
            });
        }
        group.finish();
    }

    /// Table with all wildcarded ports, tests with varying number of visas inside the table, from 1 to 1000
    pub fn bench_find_match_wildcard_ports(c: &mut Criterion) {
        let mut group = c.benchmark_group("find_match/wildcard_ports");
        for &n in &[1, 10, 100, 1000] {
            let (table, fts) = table_wildcard_ports(n);
            let ft = fts[rand::rng().random_range(0..fts.len())];
            group.bench_with_input(BenchmarkId::from_parameter(n), &ft, |b, &ft| {
                b.iter(|| table.find_match(ft));
            });
        }
        group.finish();
    }

    /// Table with one wildcarded port and n specified ports, tests with varying number of additional visas inside
    /// the table, from 1 to 1000
    /// Runs with varying group sizes within the dest port level, ranging from groups of 1 RangeMapBlaze to groups of 1000
    pub fn bench_find_match_mixed_wildcard(c: &mut Criterion) {
        let mut group = c.benchmark_group("find_match/mixed_wildcard");
        for &(n, group_size) in &[
            (100, 1),
            (100, 10),
            (100, 100),
            (1000, 1),
            (1000, 10),
            (1000, 100),
            (1000, 1000),
        ] {
            let (table, fts) = table_mixed_wildcard(n, group_size);
            let ft = fts[rand::rng().random_range(0..fts.len())];
            group.bench_with_input(
                BenchmarkId::new(format!("n={n}"), group_size),
                &ft,
                |b, &ft| {
                    b.iter(|| table.find_match(ft));
                },
            );
        }
        group.finish();
    }

    /// Table with varying dest ports, runs with varying group sizes within the dest port level,
    /// ranging from groups of 1 within the RangeMapBlaze to groups of 1000
    pub fn bench_find_match_multival_ports(c: &mut Criterion) {
        let mut group = c.benchmark_group("find_match/multival_dest_ports");
        for &(n, group_size) in &[
            (100, 1),
            (100, 10),
            (100, 100),
            (1000, 1),
            (1000, 10),
            (1000, 100),
            (1000, 1000),
        ] {
            let (table, fts) = table_multival_dest_ports(n, group_size);
            let ft = fts[rand::rng().random_range(0..fts.len())];
            group.bench_with_input(
                BenchmarkId::new(format!("n={n}"), group_size),
                &ft,
                |b, &ft| {
                    b.iter(|| table.find_match(ft));
                },
            );
        }
        group.finish();
    }

    /// Table with unique dest addrs, test looking up a visa that does not exist
    pub fn bench_find_match_miss(c: &mut Criterion) {
        let (table, _) = table_unique_dest_addrs(100);
        let miss_ft = VsapiFiveTuple::new(
            L3Type::Ipv6,
            IpAddr::from(addr_bytes_from_usize(0xFFFF_FFFF)),
            IpAddr::from([0xFFu8; 16]), // not in table
            vsapi_ip_number::TCP,
            1000,
            80,
        );
        c.bench_function("find_match/miss", |b| {
            b.iter(|| table.find_match(miss_ft));
        });
    }

    // TODO more building tests - basically it would be good to measure the building of all the different
    // table construction functions -> https://github.com/org-zpr/zpr-common/issues/36

    /// Build a table from scratch. Measures full construction including all combine logic.
    pub fn bench_build_table_from_hash(c: &mut Criterion) {
        let mut group = c.benchmark_group("build_table_from_hash");
        for &n in &[10, 100, 1000] {
            let source = addr_bytes_from_usize(0xFFFF_FFFF);
            let mut hash: HashMap<VisaId, Visa> = HashMap::with_capacity(n);
            for i in 0..n {
                hash.insert(
                    i as VisaId + 1,
                    make_visa(
                        source,
                        addr_bytes_from_usize(i),
                        vsapi_ip_number::TCP,
                        1000,
                        80,
                    )
                    .unwrap(),
                );
            }
            group.bench_with_input(BenchmarkId::from_parameter(n), &hash, |b, h| {
                b.iter(|| {
                    let table = FiveTupleLookupTable::new();
                    table.build_table_from_hash(h);
                });
            });
        }
        group.finish();
    }

    /// Single visa insertion into an existing table of varying sizes.
    /// Measures the rebuild cost of insert_visa.
    pub fn bench_insert_visa(c: &mut Criterion) {
        let mut group = c.benchmark_group("insert_visa");
        for &base_size in &[1, 10, 100] {
            let source = addr_bytes_from_usize(0xFFFF_FFFF);
            let mut hash: HashMap<VisaId, Visa> = HashMap::with_capacity(base_size);
            for i in 0..base_size {
                hash.insert(
                    i as VisaId + 1,
                    make_visa(
                        source,
                        addr_bytes_from_usize(i),
                        vsapi_ip_number::TCP,
                        1000,
                        80,
                    )
                    .unwrap(),
                );
            }
            let new_visa = make_visa(
                source,
                addr_bytes_from_usize(0xDEAD_BEEF),
                vsapi_ip_number::TCP,
                5000,
                443,
            )
            .unwrap();

            group.bench_function(BenchmarkId::from_parameter(base_size), |b| {
                b.iter_batched(
                    || {
                        let table = FiveTupleLookupTable::new();
                        table.build_table_from_hash(&hash);
                        (table, new_visa.clone())
                    },
                    |(table, visa)| table.insert_visa(9999, visa),
                    BatchSize::SmallInput,
                );
            });
        }
        group.finish();
    }
}

#[cfg(all(
    feature = "vsapi",
    any(
        feature = "rcu-aarc",
        feature = "rcu-arc-swap",
        feature = "rcu-crossbeam-epoch",
        feature = "rcu-mutex-arc",
        feature = "rcu-rwlock"
    )
))]
criterion_group!(
    benches,
    bench_impl::bench_find_match_unique_dest,
    bench_impl::bench_find_match_wildcard_ports,
    bench_impl::bench_find_match_mixed_wildcard,
    bench_impl::bench_find_match_multival_ports,
    bench_impl::bench_find_match_miss,
    bench_impl::bench_build_table_from_hash,
    bench_impl::bench_insert_visa,
);

#[cfg(all(
    feature = "vsapi",
    any(
        feature = "rcu-aarc",
        feature = "rcu-arc-swap",
        feature = "rcu-crossbeam-epoch",
        feature = "rcu-mutex-arc",
        feature = "rcu-rwlock"
    )
))]
criterion_main!(benches);

#[cfg(not(all(
    feature = "vsapi",
    any(
        feature = "rcu-aarc",
        feature = "rcu-arc-swap",
        feature = "rcu-crossbeam-epoch",
        feature = "rcu-mutex-arc",
        feature = "rcu-rwlock"
    )
)))]
fn main() {
    eprintln!("Benchmarks require 'vsapi' and an rcu feature.\n");
}
