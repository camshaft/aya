use proc_macro::TokenStream;
use proc_macro2::Span;
use quote::quote;
use syn::{parse_macro_input, Ident, ItemFn};

#[proc_macro_attribute]
pub fn integration_test(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);

    let ItemFn {
        attrs, vis, sig, ..
    } = &item;
    let name = &sig.ident;
    let name_str = &sig.ident.to_string();

    // Wrap in a netns exec
    let mut netns = false;
    let parser = syn::meta::parser(|meta| {
        if meta.path.is_ident("netns") {
            netns = true
        }
        Ok(())
    });
    parse_macro_input!(attr with parser);

    let item = if netns {
        // A vec cannot be directly expanded, and an empty #[] yields errors...
        let attrs = if attrs.is_empty() {
            quote!()
        } else {
            quote!(#[#(#attrs),*])
        };
        quote! {
            #attrs
            #vis #sig {
                #item
                let netns = crate::utils::Netns::new();
                netns.exec(|| #name());
            }
        }
    } else {
        quote!(#item)
    };

    let expanded = quote! {
        #item

        inventory::submit!(crate::IntegrationTest {
            name: concat!(module_path!(), "::", #name_str),
            test_fn: #name,
        });
    };
    TokenStream::from(expanded)
}

#[proc_macro_attribute]
pub fn tokio_integration_test(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = parse_macro_input!(item as ItemFn);
    let name = &item.sig.ident;
    let name_str = &item.sig.ident.to_string();
    let sync_name_str = format!("sync_{name_str}");
    let sync_name = Ident::new(&sync_name_str, Span::call_site());
    let expanded = quote! {
        #item

        fn #sync_name() {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(#name());
        }

        inventory::submit!(crate::IntegrationTest {
            name: concat!(module_path!(), "::", #sync_name_str),
            test_fn: #sync_name,
        });
    };
    TokenStream::from(expanded)
}
