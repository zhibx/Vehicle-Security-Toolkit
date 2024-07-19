#!/bin/expect

#
##set package_name "jakhar.aseem.diva"
set timeout -1
exec mkdir -p ./drozer-tester/logs

set isConnect "0"

proc printLogo {} {
    puts "\033\[34m"
    puts " ______  ______  _____             _               "
    puts " |  _  \\|___  / |_   _|           | |              "
    puts " | | | |   / /    | |    ___  ___ | |_   ___  _ __ "
    puts " | | | |  / /     | |   / _ \\/ __|| __| / _ \\| '__|"
    puts " | |/ / ./ /___   | |  |  __/\\__ \\| |_ |  __/| |   "
    puts " |___/  \\_____/   \\_/   \\___||___/ \\__| \\___||_|   "
    puts "                                                   "
    puts " \033\[1m"
    puts {                                      @Javeley        }
    puts {                                      github: https://github.com/JaveleyQAQ/drozer-tester}
    puts "\033\[0m"
}

proc forward_adb {} {
    if {[catch {set port [exec lsof -i:31415 | grep adb | wc -l]} result]} {
        puts "\033\[31m\[-\] 没有转发drozer默认31415端口\033\[0m"
        set port 0
    }
    if {$port == 0} {
       exec adb forward tcp:31415 tcp:31415
       puts "\033\[31m\[-\] 正在开启31415端口转发 adb forward tcp:31415 tcp:31415 \033\[0m"
    }
}
# 调用打印logo的函数
printLogo
forward_adb

proc scan_app {package_name} {
    global isConnect

    set result_file "./drozer-tester/logs/${package_name}_drozer.log"
    log_file $result_file

    if {$isConnect == 0} {
        spawn drozer console connect
        expect {
            "drozer Console" {
                set isConnect 1
            }
            "drozer Server running?" {
               puts "\033\[31m\[\-\] drozer 连接失败，请手动检查是adb/drozer否可连接！\033\[0m"
                exit 1
            }
        }
    }

    set surface   "run app.package.attacksurface $package_name"
    set finduris  "run scanner.provider.finduris -a $package_name"
    set injection "run scanner.provider.injection -a $package_name"
    set sqltables "run scanner.provider.sqltables -a $package_name"
    set traversal "run scanner.provider.traversal -a $package_name"
    set activity  "run app.activity.info -a $package_name"
    set service  "run app.service.info -a $package_name"
    set broadcast "run app.broadcast.info -a $package_name"
    set provider "run app.provider.info -a $package_name"

    puts "\033\[32m\[\+\]正在扫描 $package_name \033\[0m"

    expect "dz>"
    puts  "\033\[32m\[\+\]  查看 $package_name 攻击面 \r\033\[0m "
    send "$surface \r"

    expect "dz>"
    puts  "\033\[32m\[\+\] 扫描 $package_name finduris\r\033\[0m"
    send "$finduris \r"

    expect "dz>"
    puts  "\033\[32m\[\+\] 扫描 $package_name sqltables \r \033\[0m"
    send "$sqltables \r"

    expect "dz>"
    puts  "\033\[32m\[\+\] 扫描 $package_name 路径遍历\r \033\[0m"
    send "$traversal \r "

    expect "dz>"
    puts  "\033\[32m\[\+\] 扫描 $package_name 暴露activity \r\033\[0m"
    send "$activity \r"

    puts "\033\[33m\[\*\] 请手动测试 activity 越权访问： run app.activity.start --component $package_name/<activity> \033\[0m"

    expect "dz>"
    puts  "\033\[32m\[\+\] 扫描 $package_name service组件暴露 \r\033\[0m"
    send "$service \r"

    expect "dz>"
    puts  "\033\[32m\[\+\] 扫描 $package_name broadcast receiver组件暴露 \r\033\[0m"
    send "$broadcast \r"

    expect "dz>"
    puts  "\033\[32m\[\+\] 扫描 $package_name content provider组件暴露 \r\033\[0m"
    send "$provider \r"

    expect "dz>"
    puts  "\033\[32m\[\+\] 扫描 $package_name content provider Uri \r\033\[0m"
    send "$finduris \r"

    expect "dz>"
    puts  "\033\[32m\[\+\] 扫描 $package_name content provider SQL注入 \r\033\[0m"
    send "$injection \r"

    expect "dz>"
    puts  "\033\[32m\[\+\] 扫描 $package_name 组件导出暴露 \r\033\[0m"
    send "$surface \r"

    expect "dz>"
    puts  "\033\[32m\[\+\] 扫描 $package_name URL泄露风险 \r\033\[0m"
    send "$finduris \r"

    expect "dz>" {
        puts "\033\[32m\[\+\] 扫描 $package_name 完成 \r\033\[0m"
    }
}

if {$argc < 1} {
    puts "请提供要扫描的程序包名作为参数"
    puts ""
    puts "  \033\[35mExample:"
    puts "                  \[1\] expect drozer-tester.sh jakhar.aseem.diva"
    puts "                  \[2\] ./drozer-tester.sh jakhar.aseem.diva\033\[0m   "
    puts "             "
    puts "  -all/all        扫描所有应用程序"
    puts ""
    exit 1
}

if {[lindex $argv 0] eq "--all" || [lindex $argv 0] eq "-all" || [lindex $argv 0] eq "all" } {
    set package_list [exec adb shell pm list packages]

    # 将结果保存到文件中
    set package_file "./drozer-tester/package_list.txt"
    exec echo "$package_list" > $package_file

    set packages_count [exec cat $package_file | wc -l ]
    set packages_count [expr $packages_count - 1]
    puts "\033\[1m\033\[32m\[\+\]一共有：$packages_count 个应用\033\[0m"
    puts ""
    # 使用 for 循环扫描所有包名
    set file [open $package_file r]
    set line_count 0
    while {[gets $file line] != -1} {
        incr line_count
        set package [lindex [split $line ":"] 1]
        scan_app $package
    }

    close $file
    puts ""
    puts "\033\[1m\033\[32m\[\+\]运行日志文件保存在 ./drozer-tester/logs/ 目录下 \033\[0m "
    puts ""
    puts "文件总行数：$line_count"

    # 删除临时文件
    exec rm -f $package_file
} else {
    foreach package_name $argv {
        scan_app $package_name
        puts ""
        puts "\033\[1m\033\[32m\[\+\]运行日志文件为 ./drozer-tester/logs/${package_name}_drozer.log \033\[0m "
        puts ""
    }
}
