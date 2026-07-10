use seren::get_seren_product_examples;

fn main() {
    for example in get_seren_product_examples() {
        println!("{} ({})", example.title, example.slug);
        println!("  {}", example.description);
        for request in example.requests {
            println!(
                "  {:6} {} - {}",
                request.method.as_str(),
                request.path,
                request.label
            );
        }
        println!();
    }
}
