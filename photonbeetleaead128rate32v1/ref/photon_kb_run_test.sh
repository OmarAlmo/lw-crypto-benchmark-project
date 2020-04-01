echo "Photon encryption..."

# for file in ./../../../kb_data/*; do
#     if [ -f "$file" ]; then
#         ./photon "$file"
#     fi
# done

./photon  ./../../../kb_data/4kb.txt
./photon  ./../../../kb_data/8kb.txt
./photon  ./../../../kb_data/16kb.txt
./photon  ./../../../kb_data/32kb.txt
./photon  ./../../../kb_data/64kb.txt
./photon  ./../../../kb_data/128kb.txt
./photon  ./../../../kb_data/256kb.txt
./photon  ./../../../kb_data/512kb.txt
./photon  ./../../../kb_data/1mb.txt
./photon  ./../../../kb_data/4mb.txt
./photon  ./../../../kb_data/8mb.txt
./photon  ./../../../kb_data/16mb.txt
./photon  ./../../../kb_data/32mb.txt
./photon  ./../../../kb_data/64mb.txt

echo "Done."
