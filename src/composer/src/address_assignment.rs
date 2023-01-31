use passes::{AddressAssignmentPass, BuildState, ComponentId, SystemState, Transition};
use std::collections::HashMap;

pub struct AddressAssignmentx86_64 {
    baseaddrs: HashMap<ComponentId, u64>,
}

impl AddressAssignmentPass for AddressAssignmentx86_64 {
    fn component_baseaddr(&self, id: &ComponentId) -> u64 {
        // unwrap as we already sanitized/validated the ids.
        *self.baseaddrs.get(&id).unwrap()
    }
}

impl Transition for AddressAssignmentx86_64 {
    fn transition(s: &SystemState, _b: &mut dyn BuildState) -> Result<Box<Self>, String> {
        let ases = s.get_named();
        // This is the offset into each address space name that each
        // component starts at (unless manually overridden). This is a
        // 4MB offset, mainly just a known value significantly larger
        // than NULL = 0.
        let addr_offset = 0x400000;
        // We're assuming 64 bit systems here, and x86-64
        // specifically. This is the size of the address range in each
        // second level nodes of the page-table.
        //
        // TODO: make this math architecture-specific by adding a
        // per-architecture configuration file.
        //
        // 2^9 = # of entries per page-table node
        // (2^9)^3 = # 3 levels of page-tables
        let addrspc_name_sz = u64::pow(u64::pow(2, 9), 3) * u64::pow(2, 12);
        // 2^48 is the size of the virtual address space on x86-64, so
        // a sanity check:
        assert_eq!(addrspc_name_sz, u64::pow(2, 48) / u64::pow(2, 9));
        let mut baseaddrs = HashMap::new();
	// Track the last assigned address to a VAS, so that parent
	// relationships know where to start child addresses.
	let mut lastaddr = HashMap::new();

        for (_, a) in ases.addrspc_components_shared() {
            let mut offset = addr_offset;
	    if let Some(ref p) = a.parent {
		// Lets start our address space name where our parent
		// left off. Unwrap is OK as we've already validated
		// the name.
		offset = *lastaddr.get(p).unwrap();
	    }
            for c in &a.components {
                let id = s.get_named().rmap().get(&c).unwrap();
                baseaddrs.insert(*id, offset);
                offset += addrspc_name_sz;
            }
	    lastaddr.insert(&a.name, offset); // record the next name *past* the parent's
        }

        // All components within their own exclusive address space:
        // use the default base address, or the one that is explicitly
        // chosen within the composition script
        for c in ases.addrspc_components_exclusive() {
            let id = s.get_named().rmap().get(&c).unwrap();
            let comp = s.get_spec().component_named(&c);
            let preproc_addr = comp.base_vaddr.trim_start_matches("0x");
            let addr_wrapped = u64::from_str_radix(preproc_addr, 16);
            let mut addr = addr_offset;

            if let Ok(a) = addr_wrapped {
                addr = a;
            } else {
                println!(
                    r#"Warning (do not ignore): Cannot parse the base address, {}, for component "{}" as hexdecimal. Using default."#,
                    comp.base_vaddr, c
                );
            }

            baseaddrs.insert(*id, addr);
        }

        Ok(Box::new(AddressAssignmentx86_64 { baseaddrs }))
    }
}
