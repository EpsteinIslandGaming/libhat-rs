use proc_macro::{TokenStream, TokenTree};

fn parse_int(s: &str, base: u8) -> Option<u8> {
    u8::from_str_radix(s, base as u32).ok()
}

fn parse_signature_element(word: &str, base: u8) -> Option<(u8, u8)> {
    let mut value: u8 = 0;
    let mut mask: u8 = 0;
    for ch in word.chars() {
        value = value.wrapping_mul(base);
        mask = mask.wrapping_mul(base);
        if ch != '?' {
            let digit = parse_int(&ch.to_string(), base)?;
            value += digit;
            mask += base - 1;
        }
    }
    Some((value, mask))
}

fn parse_str(s: &str) -> Vec<(u8, u8)> {
    let mut elements = Vec::new();
    for word in s.split(' ') {
        if word.is_empty() {
            continue;
        }
        match word.len() {
            1 => {
                if word.as_bytes()[0] == b'?' {
                    elements.push((0, 0));
                } else {
                    return Vec::new();
                }
            }
            2 | 8 => {
                let base = if word.len() == 2 { 16 } else { 2 };
                if let Some(elem) = parse_signature_element(word, base) {
                    elements.push(elem);
                } else {
                    return Vec::new();
                }
            }
            _ => return Vec::new(),
        }
    }
    elements
}

fn err(msg: &str) -> TokenStream {
    format!("compile_error!({:?})", msg).parse().unwrap()
}

#[proc_macro]
pub fn sig(input: TokenStream) -> TokenStream {
    let tokens: Vec<TokenTree> = input.into_iter().collect();
    let lit = match tokens.first() {
        Some(TokenTree::Literal(l)) => l.to_string(),
        _ => return err("expected a string literal"),
    };
    let s = lit.trim_matches('"');

    let elements = parse_str(s);
    if elements.is_empty() {
        return err("invalid or empty signature");
    }
    if !elements.iter().any(|&(_, m)| m == 0xFF) {
        return err("signature must contain at least one fully-masked byte");
    }

    let n = elements.len();
    let mut out = format!(
        "{{ const SIG: [::hat::SignatureElement; {}] = [",
        n
    );
    for (i, &(value, mask)) in elements.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!(
            "::hat::SignatureElement::from_value_mask({}, {})",
            value, mask
        ));
    }
    out.push_str("]; ::hat::SignatureView::from(&SIG) }");
    out.parse().unwrap()
}
