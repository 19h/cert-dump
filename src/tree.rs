use std::collections::{HashMap, HashSet};
use crate::parser::ParsedCert;
use crate::formatter::Colors;

/// Certificate node in the tree
#[derive(Debug, Clone)]
pub struct CertNode {
    pub index: u64,
    pub sha256: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub is_self_signed: bool,
    pub children: Vec<u64>, // Indices of certificates signed by this one
}

/// Build certificate tree from parsed certificates
pub fn build_tree(
    certs: &[(impl CertInfo, Option<ParsedCert>)],
) -> Vec<TreeRoot> {
    let mut nodes: HashMap<u64, CertNode> = HashMap::new();
    let mut subject_map: HashMap<String, Vec<u64>> = HashMap::new();
    
    // First pass: create nodes and map subjects
    for (cert_info, parsed_opt) in certs {
        if let Some(parsed) = parsed_opt {
            let index = cert_info.get_global_index();
            let sha256 = cert_info.get_sha256();
            
            let is_self_signed = parsed.subject == parsed.issuer;
            
            let node = CertNode {
                index,
                sha256,
                subject: parsed.subject.clone(),
                issuer: parsed.issuer.clone(),
                serial: parsed.serial_hex.clone(),
                is_self_signed,
                children: Vec::new(),
            };
            
            // Map subject DN to certificate indices
            subject_map.entry(parsed.subject.clone())
                .or_insert_with(Vec::new)
                .push(index);
            
            nodes.insert(index, node);
        }
    }
    
    // Second pass: build parent-child relationships
    let mut has_parent: HashSet<u64> = HashSet::new();
    
    for (_, node) in nodes.iter() {
        if !node.is_self_signed {
            // Find potential parent (issuer DN matches some subject DN)
            if let Some(parent_indices) = subject_map.get(&node.issuer) {
                // If multiple matches, prefer the one that's most likely (same serial, or just first)
                // In practice, there's usually only one match
                for &parent_idx in parent_indices {
                    if parent_idx != node.index {
                        has_parent.insert(node.index);
                        // We'll add to children in the next step
                        break;
                    }
                }
            }
        }
    }
    
    // Third pass: populate children lists
    for index in nodes.keys().copied().collect::<Vec<_>>() {
        let node = &nodes[&index];
        if !node.is_self_signed {
            if let Some(parent_indices) = subject_map.get(&node.issuer) {
                for &parent_idx in parent_indices {
                    if parent_idx != index {
                        if let Some(parent_node) = nodes.get_mut(&parent_idx) {
                            if !parent_node.children.contains(&index) {
                                parent_node.children.push(index);
                            }
                        }
                        break;
                    }
                }
            }
        }
    }
    
    // Find root certificates (self-signed or no parent found)
    let mut roots = Vec::new();
    
    for (index, node) in &nodes {
        if node.is_self_signed || !has_parent.contains(index) {
            roots.push(TreeRoot {
                root_index: *index,
                is_self_signed: node.is_self_signed,
            });
        }
    }
    
    // Sort roots by index for consistent output
    roots.sort_by_key(|r| r.root_index);
    
    roots
}

/// Root of a certificate tree
#[derive(Debug, Clone)]
pub struct TreeRoot {
    pub root_index: u64,
    pub is_self_signed: bool,
}

/// Trait to abstract certificate info for both single-file and directory modes
pub trait CertInfo {
    fn get_global_index(&self) -> u64;
    fn get_sha256(&self) -> String;
}

// Implementation for single-file mode (FoundCert)
impl CertInfo for crate::scanner::FoundCert {
    fn get_global_index(&self) -> u64 {
        self.index as u64
    }
    
    fn get_sha256(&self) -> String {
        self.sha256_hex()
    }
}

// Implementation for directory mode (CertWithDuplicateInfo)
impl CertInfo for crate::dirscan::CertWithDuplicateInfo {
    fn get_global_index(&self) -> u64 {
        self.global_index
    }
    
    fn get_sha256(&self) -> String {
        self.cert.sha256_hex()
    }
}

/// Print certificate tree
pub fn print_tree(
    certs: &[(impl CertInfo, Option<ParsedCert>)],
    roots: &[TreeRoot],
    colors: &Colors,
) {
    // Build lookup map
    let mut cert_map: HashMap<u64, (String, String, String, bool)> = HashMap::new();
    let mut children_map: HashMap<u64, Vec<u64>> = HashMap::new();
    
    for (cert_info, parsed_opt) in certs {
        if let Some(parsed) = parsed_opt {
            let index = cert_info.get_global_index();
            cert_map.insert(
                index,
                (
                    parsed.subject.clone(),
                    parsed.issuer.clone(),
                    parsed.serial_hex.clone(),
                    parsed.subject == parsed.issuer,
                ),
            );
        }
    }
    
    // Rebuild children map
    for (cert_info, parsed_opt) in certs {
        if let Some(parsed) = parsed_opt {
            let index = cert_info.get_global_index();
            let is_self_signed = parsed.subject == parsed.issuer;
            
            if !is_self_signed {
                // Find parent
                for (parent_idx, (parent_subj, _, _, _)) in &cert_map {
                    if *parent_subj == parsed.issuer && *parent_idx != index {
                        children_map.entry(*parent_idx)
                            .or_insert_with(Vec::new)
                            .push(index);
                        break;
                    }
                }
            }
        }
    }
    
    println!(
        "{}{}Certificate Relationship Tree{}",
        colors.bold(),
        colors.bright_cyan(),
        colors.reset()
    );
    println!("{}{}{}", colors.cyan(), "=".repeat(80), colors.reset());
    println!();
    
    if roots.is_empty() {
        println!("{}No certificate relationships found{}", colors.dim(), colors.reset());
        return;
    }
    
    let mut visited = HashSet::new();
    
    for root in roots {
        if !visited.contains(&root.root_index) {
            print_node(
                root.root_index,
                &cert_map,
                &children_map,
                "",
                true,
                &mut visited,
                colors,
            );
        }
    }
    
    // Print orphans (certificates that couldn't be placed in tree)
    let all_indices: HashSet<u64> = cert_map.keys().copied().collect();
    let orphans: Vec<u64> = all_indices.difference(&visited).copied().collect();
    
    if !orphans.is_empty() {
        println!();
        println!(
            "{}{}Unlinked Certificates (no parent found in scan){}",
            colors.dim(),
            colors.cyan(),
            colors.reset()
        );
        println!("{}{}{}", colors.dim(), "-".repeat(80), colors.reset());
        
        for idx in orphans {
            if let Some((subj, _, _, _)) = cert_map.get(&idx) {
                println!(
                    "{}{}  Certificate #{}{} {}{}",
                    colors.dim(),
                    colors.cyan(),
                    idx,
                    colors.reset(),
                    colors.dim(),
                    truncate_dn(subj, 60)
                );
            }
        }
    }
}

fn print_node(
    index: u64,
    cert_map: &HashMap<u64, (String, String, String, bool)>,
    children_map: &HashMap<u64, Vec<u64>>,
    prefix: &str,
    is_last: bool,
    visited: &mut HashSet<u64>,
    colors: &Colors,
) {
    if visited.contains(&index) {
        // Avoid infinite loops in case of circular references
        return;
    }
    
    visited.insert(index);
    
    if let Some((subject, issuer, serial, is_self_signed)) = cert_map.get(&index) {
        // Print tree structure
        let connector = if prefix.is_empty() {
            ""
        } else if is_last {
            "└─ "
        } else {
            "├─ "
        };
        
        let self_signed_marker = if *is_self_signed {
            format!(" {}[ROOT/Self-Signed]{}", colors.green(), colors.reset())
        } else {
            String::new()
        };
        
        println!(
            "{}{}{}{}{} {}{}{}",
            colors.dim(),
            prefix,
            connector,
            colors.reset(),
            format_cert_label(index, colors),
            colors.bright_cyan(),
            truncate_dn(subject, 60),
            self_signed_marker
        );
        
        // Print additional info
        let info_prefix = if prefix.is_empty() {
            "   "
        } else if is_last {
            format!("{}   ", prefix)
        } else {
            format!("{}│  ", prefix)
        };
        
        println!(
            "{}{}Serial: {}{}",
            colors.dim(),
            info_prefix,
            serial,
            colors.reset()
        );
        
        if !is_self_signed && subject != issuer {
            println!(
                "{}{}Issued by: {}{}",
                colors.dim(),
                info_prefix,
                truncate_dn(issuer, 55),
                colors.reset()
            );
        }
        
        // Print children
        if let Some(children) = children_map.get(&index) {
            let child_prefix = if prefix.is_empty() {
                "   "
            } else if is_last {
                format!("{}   ", prefix)
            } else {
                format!("{}│  ", prefix)
            };
            
            for (i, &child_idx) in children.iter().enumerate() {
                let is_last_child = i == children.len() - 1;
                print_node(
                    child_idx,
                    cert_map,
                    children_map,
                    &child_prefix,
                    is_last_child,
                    visited,
                    colors,
                );
            }
        }
    }
}

fn format_cert_label(index: u64, colors: &Colors) -> String {
    format!(
        "{}{}Certificate #{}{}",
        colors.bold(),
        colors.cyan(),
        index,
        colors.reset()
    )
}

fn truncate_dn(dn: &str, max_len: usize) -> String {
    if dn.len() <= max_len {
        dn.to_string()
    } else {
        format!("{}...", &dn[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_truncate_dn() {
        assert_eq!(truncate_dn("CN=Short", 20), "CN=Short");
        assert_eq!(truncate_dn("CN=Very Long Distinguished Name", 15), "CN=Very Long...");
    }
}
