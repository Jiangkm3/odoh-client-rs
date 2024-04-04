for i in $(seq 1 100);
do
    target/release/odoh-client-rs -- google.come AAAA &
done
