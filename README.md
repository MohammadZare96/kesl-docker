# kesl-docker

To Build Docker just run build.sh

# To Run The Container:

docker pull mohammadzare73/kesl-service:latest

docker run --privileged -it --rm -p 8085:8085 --init -e KRAS4D_PORT=8085 -e KRAS4D_LOGLEVEL='debug' -e KRAS4D_ACTIVATION='KM8V1-WTGBS-3QBK6-EV5ZH' -e KRAS4D_FORCEUPDATE=False -v $VOLUME_ROOT/log:/var/log/kaspersky -v $VOLUME_ROOT/config:/root/kesl-service/config -v $VOLUME_ROOT/vfs-storage:/var/lib/containers/vfs-storage  mohammadzare73/kesl-service:latest


